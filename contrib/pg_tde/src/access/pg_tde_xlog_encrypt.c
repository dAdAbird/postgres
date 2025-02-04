/*-------------------------------------------------------------------------
 *
 * pg_tde_xlog_encrypt.c
 *	  Encrypted XLog storage manager
 *
 *
 * IDENTIFICATION
 *	  src/access/pg_tde_xlog_encrypt.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#ifdef PERCONA_EXT
#include "pg_tde.h"
#include "pg_tde_defines.h"
#include "access/xlog.h"
#include "access/xlog_internal.h"
#include "access/xloginsert.h"
#include "storage/bufmgr.h"
#include "storage/shmem.h"
#include "utils/guc.h"
#include "utils/memutils.h"

#include "access/pg_tde_xlog_encrypt.h"
#include "catalog/tde_global_space.h"
#include "encryption/enc_tde.h"

#ifdef FRONTEND
#include "pg_tde_fe.h"
#endif

static XLogLongPageHeaderData DecryptCurrentPageHrd;

static void SetXLogPageIVPrefix(TimeLineID tli, XLogRecPtr lsn, char *iv_prefix);

#ifndef FRONTEND
/* GUC */
static bool EncryptXLog = false;

static ssize_t TDEXLogWriteEncryptedPages(int fd, const void *buf, size_t count,
											off_t offset, TimeLineID tli,
											XLogSegNo segno);
static char *TDEXLogEncryptBuf = NULL;
static int XLOGChooseNumBuffers(void);

void
XLogInitGUC(void)
{
	DefineCustomBoolVariable("pg_tde.wal_encrypt",	/* name */
							 "Enable/Disable encryption of WAL.",	/* short_desc */
							 NULL,	/* long_desc */
							 &EncryptXLog,	/* value address */
							 false, /* boot value */
							 PGC_POSTMASTER,	/* context */
							 0, /* flags */
							 NULL,	/* check_hook */
							 NULL,	/* assign_hook */
							 NULL	/* show_hook */
		);
}

static int
XLOGChooseNumBuffers(void)
{
	int xbuffers;

	xbuffers = NBuffers / 32;
	if (xbuffers > (wal_segment_size / XLOG_BLCKSZ))
		xbuffers = (wal_segment_size / XLOG_BLCKSZ);
	if (xbuffers < 8)
		xbuffers = 8;
	return xbuffers;
}

/*
 * Defines the size of the XLog encryption buffer
 */
Size
TDEXLogEncryptBuffSize(void)
{
	int xbuffers;

	xbuffers = (XLOGbuffers == -1) ? XLOGChooseNumBuffers() : XLOGbuffers;
	return (Size) XLOG_BLCKSZ * xbuffers;
}

/*
 * Alloc memory for the encryption buffer.
 *
 * It should fit XLog buffers (XLOG_BLCKSZ * wal_buffers). We can't
 * (re)alloc this buf in tdeheap_xlog_seg_write() based on the write size as
 * it's called in the CRIT section, hence no allocations are allowed.
 *
 * Access to this buffer happens during XLogWrite() call which should
 * be called with WALWriteLock held, hence no need in extra locks.
 */
void
TDEXLogShmemInit(void)
{
	bool foundBuf;

	if (EncryptXLog)
	{
		TDEXLogEncryptBuf = (char *)
			TYPEALIGN(PG_IO_ALIGN_SIZE,
					  ShmemInitStruct("TDE XLog Encryption Buffer",
									  XLOG_TDE_ENC_BUFF_ALIGNED_SIZE,
									  &foundBuf));

		elog(DEBUG1, "pg_tde: initialized encryption buffer %lu bytes", XLOG_TDE_ENC_BUFF_ALIGNED_SIZE);
	}
}

/*
 * Encrypt XLog page(s) from the buf and write to the segment file.
 */
static ssize_t
TDEXLogWriteEncryptedPages(int fd, const void *buf, size_t count, off_t offset, 
							TimeLineID tli, XLogSegNo segno)
{
	char iv_prefix[16] = {0,};
	RelKeyData *key = GetTdeGlobaleRelationKey(GLOBAL_SPACE_RLOCATOR(XLOG_TDE_OID));
	off_t enc_off = 0;
	size_t enc_size = count;

#ifdef TDE_XLOG_DEBUG
	elog(DEBUG1, "write encrypted WAL, pages amount: %ld, size: %lu, offset: %ld [%lX], seg: %X/%X", 
					count / (Size) XLOG_BLCKSZ, count, offset, offset, LSN_FORMAT_ARGS(segno));
#endif

	/* segment's start, should be marked as encrypted and but the header should
	 * not be encrypted
	 */
	if (offset == 0)
	{
		memcpy(TDEXLogEncryptBuf, (char *) buf, SizeOfXLogLongPHD);
		((XLogLongPageHeader) (TDEXLogEncryptBuf))->std.xlp_info |= XLP_ENCRYPTED;

		enc_off = SizeOfXLogLongPHD;
		enc_size -= SizeOfXLogLongPHD;
	}

	SetXLogPageIVPrefix(tli, segno, iv_prefix);
	PG_TDE_ENCRYPT_DATA(iv_prefix, offset + enc_off,
						(char *) buf + enc_off, enc_size,
						TDEXLogEncryptBuf + enc_off, key);

	return pg_pwrite(fd, TDEXLogEncryptBuf, count, offset);
}
#endif							/* !FRONTEND */

void
TDEXLogSmgrInit(void)
{
	SetXLogSmgr(&tde_xlog_smgr);
}

ssize_t
tdeheap_xlog_seg_write(int fd, const void *buf, size_t count, off_t offset,
						TimeLineID tli, XLogSegNo segno)
{
#ifndef FRONTEND
	if (EncryptXLog)
		return TDEXLogWriteEncryptedPages(fd, buf, count, offset, tli, segno);
	else
#endif
		return pg_pwrite(fd, buf, count, offset);
}

/*
 * Read the XLog pages from the segment file and dectypt if need.
 */
ssize_t
tdeheap_xlog_seg_read(int fd, void *buf, size_t count, off_t offset, 
						TimeLineID tli, XLogSegNo segno)
{
	ssize_t readsz;
	char iv_prefix[16] = {0,};
	XLogLongPageHeader curr_page_hdr = &DecryptCurrentPageHrd;
	RelKeyData *key = GetTdeGlobaleRelationKey(GLOBAL_SPACE_RLOCATOR(XLOG_TDE_OID));
	off_t dec_off = 0;

#ifdef TDE_XLOG_DEBUG
	elog(DEBUG1, "read from a WAL segment, pages amount: %ld, size: %lu offset: %ld [%lX], seg: %X/%X", 
					count / (Size) XLOG_BLCKSZ, count, offset, offset, LSN_FORMAT_ARGS(segno));
#endif

	readsz = pg_pread(fd, buf, count, offset);

	if (offset == 0)
	{
		memcpy((char *) curr_page_hdr, (char *) buf, SizeOfXLogLongPHD);

		/* set the flag to "not encrypted" for the walreceiver */
		((XLogPageHeader) ((char *) buf))->xlp_info &= ~XLP_ENCRYPTED;
		
		dec_off = SizeOfXLogLongPHD;
		count -= SizeOfXLogLongPHD;
	}

	if (curr_page_hdr->std.xlp_info & XLP_ENCRYPTED)
	{
		// Assert(curr_page_hdr->std.xlp_tli / curr_page_hdr->xlp_seg_size == segno);
			
		SetXLogPageIVPrefix(tli, segno, iv_prefix);
		PG_TDE_DECRYPT_DATA(iv_prefix, offset + dec_off,
					(char *) buf + dec_off, count, (char *) buf + dec_off, key);
	}

	return readsz;
}

/* IV: TLI(uint32) + XLogRecPtr(uint64)*/
static inline void
SetXLogPageIVPrefix(TimeLineID tli, XLogRecPtr lsn, char *iv_prefix)
{
	iv_prefix[0] = (tli >> 24);
	iv_prefix[1] = ((tli >> 16) & 0xFF);
	iv_prefix[2] = ((tli >> 8) & 0xFF);
	iv_prefix[3] = (tli & 0xFF);

	iv_prefix[4] = (lsn >> 56);
	iv_prefix[5] = ((lsn >> 48) & 0xFF);
	iv_prefix[6] = ((lsn >> 40) & 0xFF);
	iv_prefix[7] = ((lsn >> 32) & 0xFF);
	iv_prefix[8] = ((lsn >> 24) & 0xFF);
	iv_prefix[9] = ((lsn >> 16) & 0xFF);
	iv_prefix[10] = ((lsn >> 8) & 0xFF);
	iv_prefix[11] = (lsn & 0xFF);
}

#endif /* PERCONA_EXT */
