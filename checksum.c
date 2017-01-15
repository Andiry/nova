/*
 * BRIEF DESCRIPTION
 *
 * Checksum related methods.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "nova.h"

int nova_get_entry_csum(struct super_block *sb, void *entry,
	u32 *entry_csum, size_t *size)
{
	struct nova_dentry fake_dentry;
	struct nova_file_write_entry fake_wentry;
	struct nova_setattr_logentry fake_sentry;
	struct nova_link_change_entry fake_lcentry;
	int ret = 0;
	u8 type;

	type = nova_get_entry_type(entry);
	switch (type) {
		case DIR_LOG:
			ret = memcpy_from_pmem(&fake_dentry, entry,
						NOVA_DENTRY_HEADER_LEN);
			if (ret < 0)
				break;
			*size = fake_dentry.de_len;
			ret = memcpy_from_pmem(&fake_dentry, entry, *size);
			if (ret < 0)
				break;
			*entry_csum = fake_dentry.csum;
			break;
		case FILE_WRITE:
			*size = sizeof(struct nova_file_write_entry);
			ret = memcpy_from_pmem(&fake_wentry, entry, *size);
			if (ret < 0)
				break;
			*entry_csum = fake_wentry.csum;
			break;
		case SET_ATTR:
			*size = sizeof(struct nova_setattr_logentry);
			ret = memcpy_from_pmem(&fake_sentry, entry, *size);
			if (ret < 0)
				break;
			*entry_csum = fake_sentry.csum;
			break;
		case LINK_CHANGE:
			*size = sizeof(struct nova_link_change_entry);
			ret = memcpy_from_pmem(&fake_lcentry, entry, *size);
			if (ret < 0)
				break;
			*entry_csum = fake_lcentry.csum;
			break;
		default:
			*entry_csum = 0;
			*size = 0;
			nova_dbg("%s: unknown or unsupported entry type (%d)"
				" for checksum, 0x%llx\n", __func__, type,
				(u64)entry);
			ret = -EIO;
			break;
	}

	return ret;
}

/* Calculate the entry checksum. */
u32 nova_calc_entry_csum(void *entry)
{
	u8 type;
	u32 csum = 0;
	size_t entry_len, check_len;
	void *csum_addr, *remain;

	/* Entry is checksummed excluding its csum field. */
	type = nova_get_entry_type(entry);
	switch (type) {
		/* nova_dentry has variable length due to its name. */
		case DIR_LOG:
			entry_len =  ((struct nova_dentry *) entry)->de_len;
			csum_addr = &((struct nova_dentry *) entry)->csum;
			break;
		case FILE_WRITE:
			entry_len = sizeof(struct nova_file_write_entry);
			csum_addr = &((struct nova_file_write_entry *)
					entry)->csum;
			break;
		case SET_ATTR:
			entry_len = sizeof(struct nova_setattr_logentry);
			csum_addr = &((struct nova_setattr_logentry *)
					entry)->csum;
			break;
		case LINK_CHANGE:
			entry_len = sizeof(struct nova_link_change_entry);
			csum_addr = &((struct nova_link_change_entry *)
					entry)->csum;
			break;
		default:
			entry_len = 0;
			csum_addr = NULL;
			nova_dbg("%s: unknown or unsupported entry type (%d) "
				"for checksum, 0x%llx\n", __func__, type,
				(u64) entry);
			break;
	}

	/* TODO: Check if crc32c() uses accelerated instructions for CRC. */
	if (entry_len > 0) {
		check_len = ((u8 *) csum_addr) - ((u8 *) entry);
		csum = crc32c(NOVA_INIT_CSUM, entry, check_len);
		check_len = entry_len - (check_len + NOVA_META_CSUM_LEN);
		if (check_len > 0) {
			remain = ((u8 *) csum_addr) + NOVA_META_CSUM_LEN;
			csum = crc32c(csum, remain, check_len);
		}

		if (check_len < 0) {
			nova_dbg("%s: checksum run-length error %ld < 0",
				__func__, check_len);
		}
	}

	return csum;
}

/* Update the log entry checksum. */
void nova_update_entry_csum(void *entry)
{
	u8  type = nova_get_entry_type(entry);
	u32 csum = nova_calc_entry_csum(entry);
	size_t entry_len;
	switch (type) {
		case DIR_LOG:
			((struct nova_dentry *) entry)->csum =
					cpu_to_le32(csum);
			entry_len = ((struct nova_dentry *) entry)->de_len;
			nova_dbgv("%s: update nova_dentry (%s) csum to "
				"0x%08x\n", __func__,
				((struct nova_dentry *) entry)->name, csum);
			break;
		case FILE_WRITE:
			((struct nova_file_write_entry *) entry)->csum =
					cpu_to_le32(csum);
			entry_len = sizeof(struct nova_file_write_entry);
			nova_dbgv("%s: update nova_file_write_entry csum to "
				"0x%08x\n", __func__, csum);
			break;
		case SET_ATTR:
			((struct nova_setattr_logentry *) entry)->csum =
					cpu_to_le32(csum);
			entry_len = sizeof(struct nova_setattr_logentry);
			nova_dbgv("%s: update nova_setattr_logentry csum to "
				"0x%08x\n", __func__, csum);
			break;
		case LINK_CHANGE:
			((struct nova_link_change_entry *) entry)->csum =
					cpu_to_le32(csum);
			entry_len = sizeof(struct nova_link_change_entry);
			nova_dbgv("%s: update nova_link_change_entry csum to "
				"0x%08x\n", __func__, csum);
			break;
		default:
			entry_len = 0;
			nova_dbg("%s: unknown or unsupported entry type (%d) "
				"for checksum, 0x%llx\n", __func__, type,
				(u64) entry);
			break;
	}

	if (entry_len > 0)
		nova_flush_buffer(entry, entry_len, 0);

}

bool is_entry_matched(struct super_block *sb, void *entry, size_t *ret_size)
{
	u32 checksum;
	u32 entry_csum;
	size_t size;
	bool match = false;
	int ret;

	ret = nova_get_entry_csum(sb, entry, &entry_csum, &size);
	if (ret)
		return match;

	/* No poison block */
	checksum = nova_calc_entry_csum(entry);

	match = checksum == le32_to_cpu(entry_csum);
	*ret_size = size;

	return match;
}

static bool nova_try_alter_entry(struct super_block *sb, void *entry)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	void *alter_entry;
	u64 curr, alter_curr;
	size_t size;
	bool match;

	curr = nova_get_addr_off(sbi, entry);
	alter_curr = alter_log_entry(sb, curr);
	alter_entry = (void *)nova_get_block(sb, alter_curr);

	match = is_entry_matched(sb, alter_entry, &size);

	if (!match) {
		nova_dbg("%s failed\n", __func__);
		return match;
	}

	memcpy_to_pmem_nocache(entry, alter_entry, size);
	return match;
}

int nova_update_alter_entry(struct super_block *sb, void *entry)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	void *alter_entry;
	u64 curr, alter_curr;
	u32 entry_csum;
	size_t size;
	int ret;

	if (replica_log == 0)
		return 0;

	curr = nova_get_addr_off(sbi, entry);
	alter_curr = alter_log_entry(sb, curr);
	alter_entry = (void *)nova_get_block(sb, alter_curr);

	ret = nova_get_entry_csum(sb, entry, &entry_csum, &size);
	if (ret)
		return ret;

	memcpy_to_pmem_nocache(alter_entry, entry, size);
	return 0;
}

/* Verify the log entry checksum. */
bool nova_verify_entry_csum(struct super_block *sb, void *entry)
{
	size_t size;
	bool match;

	match = is_entry_matched(sb, entry, &size);

	/* FIXME: Also check alter entry? */
	if (match)
		return match;

	if (replica_log) {
		nova_dbg("%s: nova entry mismatch detected, trying to "
				"recover from the alternative entry.\n",
				__func__);
		match = nova_try_alter_entry(sb, entry);
	}

	return match;
}

/* Calculate the data checksum. */
u32 nova_calc_data_csum(u32 init, void *buf, unsigned long size)
{
	u32 csum;

	/* TODO: Check if the function uses accelerated instructions for CRC. */
	csum = crc32c(init, buf, size);

	return csum;
}

/* Update copy-on-write data checksums.
 *
 * This function works on a sequence of contiguous data blocks that are just
 * created and the write buffer 'wrbuf' that causes this write transaction. The
 * data of 'wrbuf', and possible partial head and tail blocks are already copied
 * to NVMM data blocks.
 *
 * Logically the write buffer is in DRAM and it's checksummed before written to
 * NVMM, but if necessary 'wrbuf' can point to NVMM as well. Partial head and
 * and tail blocks are read from NVMM.
 *
 * Checksum is calculated over a whole block.
 *
 * blocknr: the physical block# of the first data block
 * wrbuf:   write buffer used to create the data blocks
 * offset:  byte offset of 'wrbuf' relative to the start the first block
 * bytes:   #bytes of 'wrbuf' written to the data blocks
 *
 * return: #bytes NOT checksummed (0 means a good exit)
 *
 * */
size_t nova_update_cow_csum(struct inode *inode, unsigned long blocknr,
		void *wrbuf, size_t offset, size_t bytes)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode  *pi = nova_get_inode(sb, inode);

	void *blockptr, *bufptr, *csum_addr;
	size_t blocksize = nova_inode_blk_size(pi);
	u32 csum;
	size_t csummed = 0;

	bufptr   = wrbuf;
	blockptr = nova_get_block(sb,
			nova_get_block_off(sb, blocknr,	pi->i_blk_type));

	/* in case file write entry is given instead of blocknr:
	 * blocknr  = get_nvmm(sb, sih, entry, entry->pgoff);
	 * blockptr = nova_get_block(sb, entry->block);
	 */

	if (offset) { // partial head block
		csum = nova_calc_data_csum(NOVA_INIT_CSUM, blockptr, offset);
		csummed = (blocksize - offset) < bytes ?
				blocksize - offset : bytes;
		csum = nova_calc_data_csum(csum, bufptr, csummed);

		if (offset + csummed < blocksize)
			csum = nova_calc_data_csum(csum,
						blockptr + offset + csummed,
						blocksize - offset - csummed);

		csum      = cpu_to_le32(csum);
		csum_addr = nova_get_data_csum_addr(sb, blocknr);
		memcpy_to_pmem_nocache(csum_addr, &csum, NOVA_DATA_CSUM_LEN);

		blocknr  += 1;
		bufptr   += csummed;
		blockptr += blocksize;
	}

	if (csummed < bytes) {
		while (csummed + blocksize < bytes) {
			csum = cpu_to_le32(nova_calc_data_csum(NOVA_INIT_CSUM,
						bufptr, blocksize));
			csum_addr = nova_get_data_csum_addr(sb, blocknr);
			memcpy_to_pmem_nocache(csum_addr, &csum,
						NOVA_DATA_CSUM_LEN);

			blocknr  += 1;
			bufptr   += blocksize;
			blockptr += blocksize;
			csummed  += blocksize;
		}

		if (csummed < bytes) { // partial tail block
			csum = nova_calc_data_csum(NOVA_INIT_CSUM, bufptr,
							bytes - csummed);
			csum = nova_calc_data_csum(csum,
						blockptr + bytes - csummed,
						blocksize - (bytes - csummed));

			csum      = cpu_to_le32(csum);
			csum_addr = nova_get_data_csum_addr(sb, blocknr);
			memcpy_to_pmem_nocache(csum_addr, &csum,
						NOVA_DATA_CSUM_LEN);

			csummed = bytes;
		}
	}

	return (bytes - csummed);
}

/* Verify checksums of requested data blocks of a file write entry.
 *
 * This function works on an existing file write 'entry' with its data in NVMM.
 *
 * Only a whole block can be checksum verified.
 *
 * index:  start block index of the file where data will be verified
 * blocks: #blocks to be verified starting from index
 *
 * return: true or false
 *
 * */
bool nova_verify_data_csum(struct inode *inode,
		struct nova_file_write_entry *entry, pgoff_t index,
		unsigned long blocks)
{
	struct super_block            *sb  = inode->i_sb;
	struct nova_inode             *pi  = nova_get_inode(sb, inode);
	struct nova_inode_info        *si  = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	void *blockptr;
	size_t blocksize = nova_inode_blk_size(pi);
	unsigned long block, blocknr;
	u32 csum_calc, csum_nvmm, *csum_addr;
	bool match;

	blocknr  = get_nvmm(sb, sih, entry, index);
	blockptr = nova_get_block(sb,
			nova_get_block_off(sb, blocknr,	pi->i_blk_type));

	match = true;
	for (block = 0; block < blocks; block++) {
		csum_calc = nova_calc_data_csum(NOVA_INIT_CSUM,
						blockptr, blocksize);
		csum_addr = nova_get_data_csum_addr(sb, blocknr);
		csum_nvmm = le32_to_cpu(*csum_addr);
		match     = (csum_calc == csum_nvmm);

		if (!match) {
			nova_dbg("%s: nova data block checksum fail! "
				"inode %lu block index %lu "
				"csum calc 0x%08x csum nvmm 0x%08x\n",
				__func__, inode->i_ino, index + block,
				csum_calc, csum_nvmm);
			break;
		}

		blocknr  += 1;
		blockptr += blocksize;
	}

	return match;
}

int nova_data_csum_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	/* allocating blocks to store data block checksums */
//	sbi->data_csum_blocks = ( (sbi->initsize >> PAGE_SHIFT)
//				* NOVA_DATA_CSUM_LEN ) >> PAGE_SHIFT;
	/* putting data checksums immediately after reserved blocks */
	/* setting this sbi->data_csum_base to zero disables data checksum */
//	sbi->data_csum_base = (sbi->reserved_blocks) << PAGE_SHIFT;

	/* Disable data checksum now as it conflicts with DAX-mmap */
	sbi->data_csum_blocks = 0;
	sbi->data_csum_base = 0;

	return 0;
}
