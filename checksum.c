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
	struct nova_snapshot_info_entry fake_snentry;
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
		case SNAPSHOT_INFO:
			*size = sizeof(struct nova_snapshot_info_entry);
			ret = memcpy_from_pmem(&fake_snentry, entry, *size);
			if (ret < 0)
				break;
			*entry_csum = fake_snentry.csum;
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
		case SNAPSHOT_INFO:
			entry_len = sizeof(struct nova_snapshot_info_entry);
			csum_addr = &((struct nova_snapshot_info_entry *)
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

	if (entry_len > 0) {
		check_len = ((u8 *) csum_addr) - ((u8 *) entry);
		csum = nova_crc32c(NOVA_INIT_CSUM, entry, check_len);
		check_len = entry_len - (check_len + NOVA_META_CSUM_LEN);
		if (check_len > 0) {
			remain = ((u8 *) csum_addr) + NOVA_META_CSUM_LEN;
			csum = nova_crc32c(csum, remain, check_len);
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
		case SNAPSHOT_INFO:
			((struct nova_snapshot_info_entry *) entry)->csum =
					cpu_to_le32(csum);
			entry_len = sizeof(struct nova_snapshot_info_entry);
			nova_dbgv("%s: update nova_snapshot_info_entry csum to "
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

static int nova_update_stripe_csum(struct super_block *sb, unsigned long strps,
	unsigned long strp_nr, u8 *strp_ptr, int zero)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned long strp;
	u32 csum;
	void *csum_addr;

	for (strp = 0; strp < strps; strp++) {
		if (zero)
			csum = sbi->zero_csum;
		else
			csum = nova_crc32c(NOVA_INIT_CSUM, strp_ptr, strp_size);

		csum = cpu_to_le32(csum);
		csum_addr = nova_get_data_csum_addr(sb, strp_nr);

		nova_memunlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);
		memcpy_to_pmem_nocache(csum_addr, &csum, NOVA_DATA_CSUM_LEN);
		nova_memlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);

		strp_nr += 1;
		if (!zero) strp_ptr += strp_size;
	}

	return 0;
}

/* Checksums a sequence of contiguous file write data stripes within one block
 * and writes the checksum values to nvmm.
 *
 * The block buffer to compute checksums should reside in dram (more trusted),
 * not in nvmm (less trusted).
 *
 * Checksum is calculated over a whole stripe.
 *
 * block:   block buffer with user data and possibly partial head-tail block
 *          - should be in kernel memory (dram) to avoid page faults
 * blocknr: destination nvmm block number where the block is written to
 *          - used to derive checksum value addresses
 * offset:  byte offset of user data in the block buffer
 * bytes:   number of user data bytes in the block buffer
 * zero:    if the user data is all zero
 */
int nova_update_block_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, u8 *block, unsigned long blocknr,
	size_t offset, size_t bytes, int zero)
{
	u8 *strp_ptr;
	size_t blockoff;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned int strp_index, strp_offset;
	unsigned long strps, strp_nr;
	timing_t block_csum_time;

	NOVA_START_TIMING(block_csum_t, block_csum_time);
	blockoff = nova_get_block_off(sb, blocknr, sih->i_blk_type);

	/* strp_index: stripe index within the block buffer
	 * strp_offset: stripe offset within the block buffer
	 *
	 * strps: number of stripes touched by user data (need new checksums)
	 * strp_nr: global stripe number converted from blocknr and offset
	 * strp_ptr: pointer to stripes in the block buffer */
	strp_index = offset >> strp_shift;
	strp_offset = offset - (strp_index << strp_shift);

	strps = ((strp_offset + bytes - 1) >> strp_shift) + 1;
	strp_nr = (blockoff + offset) >> strp_shift;
	strp_ptr = block + (strp_index << strp_shift);

	nova_update_stripe_csum(sb, strps, strp_nr, strp_ptr, zero);

	NOVA_END_TIMING(block_csum_t, block_csum_time);

	return 0;
}

int nova_update_pgoff_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long pgoff, int zero)
{
	void *dax_mem = NULL;
	u64 blockoff;
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned long strp_nr;
	int count;

	count = blk_type_to_size[sih->i_blk_type] / strp_size;

	blockoff = nova_find_nvmm_block(sb, sih, entry, pgoff);

	/* Truncated? */
	if (blockoff == 0)
		return 0;

	dax_mem = nova_get_block(sb, blockoff);

	strp_nr = blockoff >> strp_shift;

	nova_update_stripe_csum(sb, count, strp_nr, dax_mem, zero);

	return 0;
}

/* Verify checksums of requested data bytes starting from offset of blocknr.
 *
 * Only a whole stripe can be checksum verified.
 *
 * blocknr: container blocknr for the first stripe to be verified
 * offset:  byte offset within the block associated with blocknr
 * bytes:   number of contiguous bytes to be verified starting from offset
 *
 * return: true or false
 * */
bool nova_verify_data_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr,
	size_t offset, size_t bytes)
{
	void *blockptr, *strp_ptr;
	size_t blockoff, blocksize = nova_inode_blk_size(sih);
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned int strp_index;
	unsigned long strp, strps, strp_nr;
	u32 csum_calc, csum_nvmm, *csum_addr;
	bool match;
	timing_t verify_time;

	NOVA_START_TIMING(verify_csum_t, verify_time);

	/* Only a whole stripe can be checksum verified.
	 * strps: # of stripes to be checked since offset. */
	strps = ((offset + bytes - 1) >> strp_shift) - (offset >> strp_shift) + 1;

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
		csum_calc = nova_crc32c(NOVA_INIT_CSUM, strp_ptr, strp_size);
		csum_addr = nova_get_data_csum_addr(sb, strp_nr);
		csum_nvmm = le32_to_cpu(*csum_addr);
		match     = (csum_calc == csum_nvmm);

		if (!match) {
			nova_dbg("%s: nova data stripe checksum fail! "
				"inode %lu, strp %lu of %lu, "
				"block offset %lu, stripe nr %lu, "
				"csum calc 0x%08x, csum nvmm 0x%08x\n",
				__func__, sih->ino, strp, strps,
				blockoff, strp_nr,
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

	NOVA_END_TIMING(verify_csum_t, verify_time);
	return match;
}

int nova_copy_partial_block_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long index, size_t offset, unsigned long dst_blknr,
	bool is_end_blk)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long src_blknr;
	unsigned int csum_size = NOVA_DATA_CSUM_LEN;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned int num_strps;
	unsigned long src_strp_nr, dst_strp_nr;
	size_t src_blk_off, dst_blk_off;
	u32 zero_csum;
	u32 *src_csum_ptr, *dst_csum_ptr;

	dst_blk_off = nova_get_block_off(sb, dst_blknr, sih->i_blk_type);

	if (entry != NULL) {
		src_blknr = get_nvmm(sb, sih, entry, index);
		src_blk_off = nova_get_block_off(sb, src_blknr, sih->i_blk_type);
	}

	/* num_strps: the number of unmodified stripes, i.e. their checksums do
	 * not change. */
	if (is_end_blk) {
		dst_strp_nr = ((dst_blk_off + offset - 1) >> strp_shift) + 1;
		dst_csum_ptr = nova_get_data_csum_addr(sb, dst_strp_nr);
		num_strps = (sb->s_blocksize - offset) >> strp_shift;
	} else {
		dst_strp_nr = dst_blk_off >> strp_shift;
		dst_csum_ptr = nova_get_data_csum_addr(sb, dst_strp_nr);
		num_strps = offset >> strp_shift;
	}

	/* copy source checksums only if they exist */
	if (entry != NULL && is_end_blk) {
		src_strp_nr = ((src_blk_off + offset - 1) >> strp_shift) + 1;
		src_csum_ptr = nova_get_data_csum_addr(sb, src_strp_nr);
	} else if (entry != NULL && !is_end_blk) {
		src_strp_nr = src_blk_off >> strp_shift;
		src_csum_ptr = nova_get_data_csum_addr(sb, src_strp_nr);
	} else { // entry == NULL
		/* According to nova_handle_head_tail_blocks():
		 * NULL-entry partial blocks are zero-ed */
		zero_csum = cpu_to_le32(sbi->zero_csum);
		src_csum_ptr = &zero_csum;
	}

	while (num_strps > 0) {
		if (src_csum_ptr == NULL || dst_csum_ptr == NULL) {
			nova_err(sb, "%s: invalid checksum addresses "
			"src_csum_ptr 0x%p, dst_csum_ptr 0x%p\n", __func__);

			return -EFAULT;
		}

		/* TODO: Handle MCE: src_csum_ptr read from NVMM */
		nova_memunlock_range(sb, dst_csum_ptr, csum_size);
		memcpy_from_pmem(dst_csum_ptr, src_csum_ptr, csum_size);
		nova_memlock_range(sb, dst_csum_ptr, csum_size);
		nova_flush_buffer(dst_csum_ptr, csum_size, 0);

		num_strps--;
		dst_csum_ptr++;
		if (entry != NULL) src_csum_ptr++;
	}

	return 0;
}

int nova_update_truncated_block_csum(struct super_block *sb,
	struct inode *inode, loff_t newsize) {

	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned long offset = newsize & (sb->s_blocksize - 1);
	unsigned long pgoff, length;
	u64 nvmm;
	char *nvmm_addr, *strp_addr, *tail_strp = NULL;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned int strp_index, strp_offset;
	unsigned long strps, strp_nr;

	length = sb->s_blocksize - offset;
	pgoff = newsize >> sb->s_blocksize_bits;

	nvmm = nova_find_nvmm_block(sb, sih, NULL, pgoff);
	if (nvmm == 0)
		return -EFAULT;

	nvmm_addr = (char *)nova_get_block(sb, nvmm);

	strp_index = offset >> strp_shift;
	strp_offset = offset - (strp_index << strp_shift);

	strps = ((strp_offset + length - 1) >> strp_shift) + 1;
	strp_nr = (nvmm + offset) >> strp_shift;
	strp_addr = nvmm_addr + (strp_index << strp_shift);

	if (strp_offset > 0) {
		/* Copy to DRAM to catch MCE.
		tail_strp = kzalloc(strp_size, GFP_KERNEL);
		if (tail_strp == NULL) {
			nova_err(sb, "%s: buffer allocation error\n", __func__);
			return -ENOMEM;
		}
		memcpy_from_pmem(tail_strp, strp_addr, strp_offset);
		*/
		tail_strp = strp_addr;
		nova_update_stripe_csum(sb, 1, strp_nr, tail_strp, 0);

		strps--;
		strp_nr++;
	}

	if (strps > 0) nova_update_stripe_csum(sb, strps, strp_nr, NULL, 1);

//	if (tail_strp != NULL) kfree(tail_strp);

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

