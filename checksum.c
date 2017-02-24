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

static int nova_get_entry_csum(struct super_block *sb, void *entry,
	u32 *entry_csum, size_t *size)
{
	struct nova_dentry fake_dentry;
	struct nova_file_write_entry fake_wentry;
	struct nova_setattr_logentry fake_sentry;
	struct nova_link_change_entry fake_lcentry;
	struct nova_mmap_entry fake_mmapentry;
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
		case MMAP_WRITE:
			*size = sizeof(struct nova_mmap_entry);
			ret = memcpy_from_pmem(&fake_mmapentry, entry, *size);
			if (ret < 0)
				break;
			*entry_csum = fake_mmapentry.csum;
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
static u32 nova_calc_entry_csum(void *entry)
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
		case MMAP_WRITE:
			entry_len = sizeof(struct nova_mmap_entry);
			csum_addr = &((struct nova_mmap_entry *)
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
	u8  type;
	u32 csum;
	size_t entry_len = CACHELINE_SIZE;

	/* No point to update csum if replica log is disabled */
	if (replica_metadata == 0 || metadata_csum == 0)
		goto flush;

	type = nova_get_entry_type(entry);
	csum = nova_calc_entry_csum(entry);

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
		case MMAP_WRITE:
			((struct nova_mmap_entry *) entry)->csum =
					cpu_to_le32(csum);
			entry_len = sizeof(struct nova_mmap_entry);
			nova_dbgv("%s: update nova_mmap_entry csum to "
				"0x%08x\n", __func__, csum);
			break;
		default:
			entry_len = 0;
			nova_dbg("%s: unknown or unsupported entry type (%d) "
				"for checksum, 0x%llx\n", __func__, type,
				(u64) entry);
			break;
	}

flush:
	if (entry_len > 0)
		nova_flush_buffer(entry, entry_len, 0);

}

static bool is_entry_matched(struct super_block *sb, void *entry,
	size_t *ret_size)
{
	u32 checksum;
	u32 entry_csum;
	size_t size;
	bool match = false;
	int ret;

	ret = nova_get_entry_csum(sb, entry, &entry_csum, &size);
	if (ret)
		return match;

	*ret_size = size;

	/* No need to verify checksum if replica metadata disabled */
	if (replica_metadata == 0 || metadata_csum == 0)
		return true;

	/* No poison block */
	checksum = nova_calc_entry_csum(entry);

	match = checksum == le32_to_cpu(entry_csum);

	return match;
}

static bool nova_try_alter_entry(struct super_block *sb, void *entry,
	bool original_match)
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
		if (original_match) {
			memcpy_to_pmem_nocache(alter_entry, entry, size);
			match = original_match;
		}
		return match;
	}

	if (memcmp(entry, alter_entry, size))
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

	if (replica_metadata == 0)
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

	if (replica_metadata == 0)
		return match;

	if (!match)
		nova_dbg("%s: nova entry mismatch detected, trying to "
				"recover from the alternative entry.\n",
				__func__);

	match = nova_try_alter_entry(sb, entry, match);

	return match;
}

int nova_check_alter_entry(struct super_block *sb, u64 curr)
{
	void *addr, *alter_addr;
	u64 alter;
	size_t size;
	u32 entry_csum;
	int ret = 0;

	if (replica_metadata == 0)
		return 0;

	addr = (void *)nova_get_block(sb, curr);
	ret = nova_get_entry_csum(sb, addr, &entry_csum, &size);
	if (ret)
		return ret;

	alter = alter_log_entry(sb, curr);
	alter_addr = (void *)nova_get_block(sb, alter);
	ret = memcmp(addr, alter_addr, size);

	if (ret) {
		nova_dbg("%s: alter entry dismatch\n", __func__);
		nova_dbg("Main entry:\n");
		nova_print_log_entry(sb, curr);
		nova_dbg("Alter entry:\n");
		nova_print_log_entry(sb, alter);
		return ret;
	}

	return ret;
}

int nova_check_inode_integrity(struct super_block *sb, u64 ino,
	u64 pi_addr, u64 alter_pi_addr)
{
	struct nova_inode *pi = NULL, *alter_pi = NULL;
	struct nova_inode fake_pi, alter_fake_pi;
	int diff = 0;
	int ret;
	int pi_good = 1, alter_pi_good = 0;

	ret = nova_get_reference(sb, pi_addr, &fake_pi,
			(void **)&pi, sizeof(struct nova_inode));
	if (ret) {
		nova_dbg("%s: read pi @ 0x%llx failed\n",
				__func__, pi_addr);
		pi_good = 0;
	}

	if (replica_metadata == 0) {
		/* We cannot do much */
		return ret;
	}

	alter_pi_good = 1;
	ret = nova_get_reference(sb, alter_pi_addr, &alter_fake_pi,
				(void **)&alter_pi, sizeof(struct nova_inode));
	if (ret) {
		nova_dbg("%s: read alter pi @ 0x%llx failed\n",
					__func__, alter_pi_addr);
		alter_pi_good = 0;
	}

	if (pi_good == 0 && alter_pi_good == 0)
		goto out;

	if (pi_good == 0) {
		nova_memunlock_inode(sb, pi);
		memcpy_to_pmem_nocache(pi, alter_pi,
					sizeof(struct nova_inode));
		nova_memlock_inode(sb, pi);
	} else if (alter_pi_good == 0) {
		nova_memunlock_inode(sb, alter_pi);
		memcpy_to_pmem_nocache(alter_pi, pi,
					sizeof(struct nova_inode));
		nova_memlock_inode(sb, alter_pi);
	}

	if (memcmp(pi, alter_pi, sizeof(struct nova_inode))) {
		nova_err(sb, "%s: inode %llu shadow mismatch\n",
						__func__, ino);
		nova_print_inode(pi);
		nova_print_inode(alter_pi);
		diff = 1;
	}

	ret = nova_check_inode_checksum(&fake_pi);
	nova_dbgv("%s: %d\n", __func__, ret);
	if (ret == 0) {
		if (diff) {
			nova_dbg("Update shadow inode with original inode\n");
			nova_memunlock_inode(sb, alter_pi);
			memcpy_to_pmem_nocache(alter_pi, pi,
						sizeof(struct nova_inode));
			nova_memlock_inode(sb, alter_pi);
		}
		return ret;
	}

	if (alter_pi_good == 0)
		goto out;

	ret = nova_check_inode_checksum(&alter_fake_pi);
	if (ret == 0) {
		if (diff) {
			nova_dbg("Update original inode with shadow inode\n");
			nova_memunlock_inode(sb, pi);
			memcpy_to_pmem_nocache(pi, alter_pi,
						sizeof(struct nova_inode));
			nova_memlock_inode(sb, pi);
		}
		return ret;
	}

out:
	/* We are in big trouble */
	nova_err(sb, "%s: inode %llu check failure\n", __func__, ino);
	return -EIO;
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
 * This function works on a sequence of contiguous data stripes that are just
 * created and the write buffer 'wrbuf' that causes this write transaction. The
 * data of 'wrbuf', and possible partial head and tail stripes are already
 * copied to NVMM data blocks.
 *
 * Logically the write buffer is in DRAM and it's checksummed before written to
 * NVMM, but if necessary 'wrbuf' can point to NVMM as well. Partial head and
 * and tail stripes are read from NVMM.
 * TODO: This partial read should be protected from MCEs.
 *
 * Checksum is calculated over a whole stripe.
 *
 * blocknr: the physical block# of the first data block
 * wrbuf:   write buffer used to create the data blocks
 * offset:  byte offset of 'wrbuf' relative to the start the first block
 * bytes:   #bytes of 'wrbuf' written to the data blocks
 *
 * return:  #bytes NOT checksummed (0 means a good exit)
 *
 * */
size_t nova_update_cow_csum(struct inode *inode, unsigned long blocknr,
		void *wrbuf, size_t offset, size_t bytes)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info        *si  = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	void *blockptr, *strp_ptr, *bufptr, *csum_addr;
	size_t blockoff;
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned int strp_index, strp_offset;
	unsigned long strp_nr;
	u32 csum;
	size_t csummed = 0;

	bufptr   = wrbuf;
	blockoff = nova_get_block_off(sb, blocknr, sih->i_blk_type);
	blockptr = nova_get_block(sb, blockoff);

	/* strp_nr: global stripe number converted from blocknr and offset
	 * strp_ptr: virtual address of the 1st stripe
	 * strp_index: stripe index within a block
	 * strp_offset: byte offset within the 1st stripe */
	strp_nr = (blockoff + offset) >> strp_shift;
	strp_index = offset >> strp_shift;
	strp_ptr = blockptr + (strp_index << strp_shift);
	strp_offset = offset - (strp_index << strp_shift);

	/* in case file write entry is given instead of blocknr:
	 * blocknr  = get_nvmm(sb, sih, entry, entry->pgoff);
	 * blockptr = nova_get_block(sb, entry->block);
	 */

	if (strp_offset) { // partial head stripe
		csum = nova_calc_data_csum(NOVA_INIT_CSUM,
					strp_ptr, strp_offset);
		csummed = (strp_size - strp_offset) < bytes ?
				strp_size - strp_offset : bytes;
		csum = nova_calc_data_csum(csum, bufptr, csummed);

		if (strp_offset + csummed < strp_size)
			/* Now bytes are less than a stripe size.
			 * Need to checksum the stripe's unchanged bytes. */
			csum = nova_calc_data_csum(csum,
					strp_ptr + strp_offset + csummed,
					strp_size - strp_offset - csummed);

		csum      = cpu_to_le32(csum);
		csum_addr = nova_get_data_csum_addr(sb, strp_nr);
		nova_memunlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);
		memcpy_to_pmem_nocache(csum_addr, &csum, NOVA_DATA_CSUM_LEN);
		nova_memlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);

		strp_nr  += 1;
		bufptr   += csummed;
		strp_ptr += strp_size;
	}

	if (csummed < bytes) {
		while (csummed + strp_size < bytes) {
			csum = cpu_to_le32(nova_calc_data_csum(NOVA_INIT_CSUM,
						bufptr, strp_size));
			csum_addr = nova_get_data_csum_addr(sb, strp_nr);
			nova_memunlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);
			memcpy_to_pmem_nocache(csum_addr, &csum,
						NOVA_DATA_CSUM_LEN);
			nova_memlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);

			strp_nr  += 1;
			bufptr   += strp_size;
			strp_ptr += strp_size;
			csummed  += strp_size;
		}

		if (csummed < bytes) { // partial tail stripe
			csum = nova_calc_data_csum(NOVA_INIT_CSUM, bufptr,
							bytes - csummed);
			csum = nova_calc_data_csum(csum,
						strp_ptr + bytes - csummed,
						strp_size - (bytes - csummed));

			csum      = cpu_to_le32(csum);
			csum_addr = nova_get_data_csum_addr(sb, strp_nr);
			nova_memunlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);
			memcpy_to_pmem_nocache(csum_addr, &csum,
						NOVA_DATA_CSUM_LEN);
			nova_memlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);

			csummed = bytes;
		}
	}

	return (bytes - csummed);
}

int nova_update_block_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long pgoff)
{
	void *dax_mem = NULL, *csum_addr;
	u64 blockoff;
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned long strp_nr;
	u32 csum;
	int i;
	int count;

	count = blk_type_to_size[sih->i_blk_type] / strp_size;

	blockoff = nova_find_nvmm_block(sb, sih, entry, pgoff);

	/* Truncated? */
	if (blockoff == 0)
		return 0;

	dax_mem = nova_get_block(sb, blockoff);

	strp_nr = blockoff >> strp_shift;

	for (i = 0; i < count; i++) {
		csum = cpu_to_le32(nova_calc_data_csum(NOVA_INIT_CSUM,
						dax_mem, strp_size));
		csum_addr = nova_get_data_csum_addr(sb, strp_nr);
		nova_memunlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);
		memcpy_to_pmem_nocache(csum_addr, &csum,
					NOVA_DATA_CSUM_LEN);
		nova_memlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);

		strp_nr  += 1;
		dax_mem  += strp_size;
	}

	return 0;
}

/* Verify checksums of requested data bytes of a file write entry.
 *
 * This function works on an existing file write 'entry' with its data in NVMM.
 *
 * Only a whole stripe can be checksum verified.
 *
 * index:  start block index of the file where data will be verified
 * offset: byte offset within the start block
 * bytes:  number of bytes to be checked starting from offset
 *
 * return: true or false
 *
 * */
bool nova_verify_data_csum(struct inode *inode,
		struct nova_file_write_entry *entry, pgoff_t index,
		size_t offset, size_t bytes)
{
	struct super_block            *sb  = inode->i_sb;
	struct nova_inode_info        *si  = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	void *blockptr, *strp_ptr;
	size_t blockoff;
	size_t blocksize = nova_inode_blk_size(sih);
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned long blocknr;
	unsigned int strp_index;
	unsigned long strp, strps, strp_nr;
	u32 csum_calc, csum_nvmm, *csum_addr;
	bool match;

	/* Only a whole stripe can be checksum verified.
	 * strps: # of stripes to be checked since offset. */
	strps = ((offset + bytes - 1) >> strp_shift) - (offset >> strp_shift) + 1;

	blocknr  = get_nvmm(sb, sih, entry, index);
	blockoff = nova_get_block_off(sb, blocknr, sih->i_blk_type);
	blockptr = nova_get_block(sb, blockoff);

	/* strp_nr: global stripe number converted from blocknr and offset
	 * strp_ptr: virtual address of the 1st stripe
	 * strp_index: stripe index within a block */
	strp_nr = (blockoff + offset) >> strp_shift;
	strp_index = offset >> strp_shift;
	strp_ptr = blockptr + (strp_index << strp_shift);

	match = true;
	for (strp = 0; strp < strps; strp++) {
		csum_calc = nova_calc_data_csum(NOVA_INIT_CSUM,
						strp_ptr, strp_size);
		csum_addr = nova_get_data_csum_addr(sb, strp_nr);
		csum_nvmm = le32_to_cpu(*csum_addr);
		match     = (csum_calc == csum_nvmm);

		if (!match) {
			nova_dbg("%s: nova data stripe checksum fail! "
				"inode %lu block offset %lu stripe nr %lu "
				"csum calc 0x%08x csum nvmm 0x%08x\n",
				__func__, inode->i_ino, blockoff, strp_nr,
				csum_calc, csum_nvmm);

			if (data_parity > 0)
				nova_dbg("%s: nova data recovery begins.\n",
						__func__);
			else
				break;

			if (nova_restore_data(sb, blocknr, strp_index) == 0) {
				nova_dbg("%s: nova data recovery success!\n",
						__func__);
				match = true;
			} else {
				nova_dbg("%s: nova data recovery fail!\n",
						__func__);
				break;
			}
		}

		strp_nr    += 1;
		strp_index += 1;
		strp_ptr   += strp_size;
		if (strp_index == (blocksize >> strp_shift)) {
			blocknr += 1;
			blockoff += blocksize;
			strp_index = 0;
		}

	}

	return match;
}

int nova_copy_partial_block_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long index, size_t offset, unsigned long dst_blknr,
	bool is_end_blk)
{
	unsigned long src_blknr;
	unsigned int csum_size = NOVA_DATA_CSUM_LEN;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned int num_strps;
	unsigned long src_strp_nr, dst_strp_nr;
	size_t src_blk_off, dst_blk_off;
	void *src_csum_ptr, *dst_csum_ptr;

	src_blknr = get_nvmm(sb, sih, entry, index);
	src_blk_off = nova_get_block_off(sb, src_blknr, sih->i_blk_type);
	dst_blk_off = nova_get_block_off(sb, dst_blknr, sih->i_blk_type);

	/* num_strps: the number of unmodified stripes, i.e. their checksums do
	 * not change. */
	if (is_end_blk) {
		src_strp_nr = ((src_blk_off + offset - 1) >> strp_shift) + 1;
		dst_strp_nr = ((dst_blk_off + offset - 1) >> strp_shift) + 1;
		src_csum_ptr = nova_get_data_csum_addr(sb, src_strp_nr);
		dst_csum_ptr = nova_get_data_csum_addr(sb, dst_strp_nr);
		num_strps = (sb->s_blocksize - offset) >> strp_shift;
	}
	else {
		src_strp_nr = src_blk_off >> strp_shift;
		dst_strp_nr = dst_blk_off >> strp_shift;
		src_csum_ptr = nova_get_data_csum_addr(sb, src_strp_nr);
		dst_csum_ptr = nova_get_data_csum_addr(sb, dst_strp_nr);
		num_strps = offset >> strp_shift;
	}

	if (num_strps > 0) {
		if ((src_csum_ptr == NULL) || (dst_csum_ptr == NULL)) {
			nova_err(sb, "%s: invalid checksum addresses "
			"src_csum_ptr 0x%p, dst_csum_ptr 0x%p\n", __func__);

			return -EIO;
		}

		/* TODO: Handle MCE: src_csum_ptr read from NVMM */
		/* Should memunlock, if it's not already unlocked by caller. */
		memcpy_from_pmem(dst_csum_ptr, src_csum_ptr,
					num_strps * csum_size);
	}

	return 0;
}

int nova_data_csum_init_free_list(struct super_block *sb,
	struct free_list *free_list)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long data_csum_blocks;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;

	/* Allocate blocks to store data block checksums.
	 * Always reserve in case user turns it off at init mount but later
	 * turns it on. */
	data_csum_blocks = ( (sbi->initsize >> strp_shift)
				* NOVA_DATA_CSUM_LEN ) >> PAGE_SHIFT;
	free_list->csum_start = free_list->block_start;
	free_list->block_start += data_csum_blocks / sbi->cpus;
	if (data_csum_blocks % sbi->cpus)
		free_list->block_start++;

	free_list->num_csum_blocks =
		free_list->block_start - free_list->csum_start;

	return 0;
}

