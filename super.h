#ifndef __SUPER_H
#define __SUPER_H
/*
 * Structure of the NOVA super block in PMEM
 *
 * The fields are partitioned into static and dynamic fields. The static fields
 * never change after file system creation. This was primarily done because
 * nova_get_block() returns NULL if the block offset is 0 (helps in catching
 * bugs). So if we modify any field using journaling (for consistency), we
 * will have to modify s_sum which is at offset 0. So journaling code fails.
 * This (static+dynamic fields) is a temporary solution and can be avoided
 * once the file system becomes stable and nova_get_block() returns correct
 * pointers even for offset 0.
 */
struct nova_super_block {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below
	 */
	__le32		s_sum;			/* checksum of this sb */
	__le32		s_magic;		/* magic signature */
	__le32		s_padding32;
	__le32		s_blocksize;		/* blocksize in bytes */
	__le64		s_size;			/* total size of fs in bytes */
	char		s_volume_name[16];	/* volume name */

	/* all the dynamic fields should go here */
	__le64		s_epoch_id;		/* Epoch ID */

	/* s_mtime and s_wtime should be together and their order should not be
	 * changed. we use an 8 byte write to update both of them atomically
	 */
	__le32		s_mtime;		/* mount time */
	__le32		s_wtime;		/* write time */
} __attribute((__packed__));

#define NOVA_SB_SIZE 512       /* must be power of two */

/* ======================= Reserved blocks ========================= */

/*
 * Page 0 contains super blocks;
 * Page 1 contains reserved inodes;
 * Page 2 - 15 are reserved.
 * Page 16 - 31 contain pointers to inode tables.
 * Page 32 - 47 contain pointers to journal pages.
 */
#define	HEAD_RESERVED_BLOCKS	64
#define	NUM_JOURNAL_PAGES	16

#define	SUPER_BLOCK_START       0 // Superblock
#define	RESERVE_INODE_START	1 // Reserved inodes
#define	INODE_TABLE_START	16 // inode table pointers
#define	JOURNAL_START		32 // journal pointer table

/* For replica super block and replica reserved inodes */
#define	TAIL_RESERVED_BLOCKS	2

/* ======================= Reserved inodes ========================= */

/* We have space for 31 reserved inodes */
enum {
	NOVA_ROOT_INO = 1,	/* Root inode */
	NOVA_INODETABLE_INO,	/* Fake inode associated with inode
				 * stroage.  We need this because our
				 * allocator requires inode to be
				 * associated with each allocation.
				 * The data actually lives in linked
				 * lists in INODE_TABLE_START. */
	NOVA_BLOCKNODE_INO,	/* Storage for allocator state */
	NOVA_LITEJOURNAL_INO,	/* Storage for lightweight journals */
	NOVA_INODELIST_INO	/* Storage for Inode free list */
};


/* Normal inode starts at 32 */
#define NOVA_NORMAL_INODE_START      (32)


/*
 * NOVA super-block data in DRAM
 */
struct nova_sb_info {
	struct super_block *sb;			/* VFS super block */
	struct nova_super_block *nova_sb;	/* DRAM copy of SB */
	struct block_device *s_bdev;
	struct dax_device *s_dax_dev;

	/*
	 * base physical and virtual address of NOVA (which is also
	 * the pointer to the super block)
	 */
	phys_addr_t	phys_addr;
	void		*virt_addr;
	void		*replica_reserved_inodes_addr;
	void		*replica_sb_addr;

	unsigned long	num_blocks;

	/* Mount options */
	unsigned long	bpi;
	unsigned long	blocksize;
	unsigned long	initsize;
	unsigned long	s_mount_opt;
	kuid_t		uid;    /* Mount uid for root directory */
	kgid_t		gid;    /* Mount gid for root directory */
	umode_t		mode;   /* Mount mode for root directory */
	atomic_t	next_generation;
	/* inode tracking */
	unsigned long	s_inodes_used_count;
	unsigned long	head_reserved_blocks;
	unsigned long	tail_reserved_blocks;

	struct mutex	s_lock;	/* protects the SB's buffer-head */

	int cpus;
	struct proc_dir_entry *s_proc;

	/* Current epoch. volatile guarantees visibility */
	volatile u64 s_epoch_id;

	/* ZEROED page for cache page initialized */
	void *zeroed_page;

	/* Per-CPU journal lock */
	spinlock_t *journal_locks;

	/* Per-CPU inode map */
	struct inode_map	*inode_maps;

	/* Decide new inode map id */
	unsigned long map_id;

	/* Per-CPU free block list */
	struct free_list *free_lists;
	unsigned long per_list_blocks;
};

static inline struct nova_sb_info *NOVA_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct nova_super_block
*nova_get_redund_super(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return (struct nova_super_block *)(sbi->replica_sb_addr);
}


/* If this is part of a read-modify-write of the super block,
 * nova_memunlock_super() before calling!
 */
static inline struct nova_super_block *nova_get_super(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return (struct nova_super_block *)sbi->virt_addr;
}

extern void nova_error_mng(struct super_block *sb, const char *fmt, ...);
extern struct nova_range_node *nova_alloc_range_node(struct super_block *sb);
extern struct nova_range_node *nova_alloc_inode_node(struct super_block *sb);
extern struct nova_range_node *nova_alloc_dir_node(struct super_block *sb);
extern struct nova_file_write_item *
nova_alloc_file_write_item(struct super_block *sb);
extern void nova_free_range_node(struct nova_range_node *node);
extern void nova_free_inode_node(struct nova_range_node *node);
extern void nova_free_dir_node(struct nova_range_node *node);
void nova_free_file_write_item(struct nova_file_write_item *item);

#endif
