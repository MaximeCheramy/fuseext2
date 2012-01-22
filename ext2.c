#include <errno.h>
#include <stdio.h>
#include <fuse.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <sys/time.h>

#include "ext2.h"

#define EXT2_ROOT_INO 2

#define max(a,b) ((a) > (b) ? (a) : (b))

static struct blk_t* addr_inode_data(int inode);
static void show_inode(int i);
static uint32_t alloc_block();
static int ext2_mknod(const char * path, mode_t mode, dev_t dev);

char *strchrnul(const char *s, int c) {
	char *i;
	for (i = (char*)s; *i != '\0'; ++i) {
		if (*i == c) {
			return i;
		}
	}
	return i;
}

struct ext2_options
{
	char* device;
} options;

static struct fuse_opt ext2_fuse_opts[] =
{
	{ "-device=%s", offsetof(struct ext2_options, device), 0 },
};

static int fd;
static struct ext2_super_block superblock;
static struct ext2_group_desc *group_desc_table;
static int n_groups;

FILE* debug;

static void split_dir_filename(const char * path, char * dir, char * filename) {
	char *p = strrchr(path, '/');
	strcpy(filename, p+1);
	for (; path < p; path++, dir++) {
		*dir = *path;
	} 
	*dir = '\0';
}

static void show_info() {
	fprintf(stderr, "Nombre d'inodes : %d\n", superblock.s_inodes_count);
	fprintf(stderr, "Taille d'un inode : %d\n", superblock.s_inode_size);
	fprintf(stderr, "Blocks libres : %d\n", superblock.s_free_blocks_count);
	fprintf(stderr, "Inodes libres : %d\n", superblock.s_free_inodes_count);
	fprintf(stderr, "Taille block : %d\n", 1024 << superblock.s_log_block_size);
	fprintf(stderr, "Blocks par groupe : %d\n", superblock.s_blocks_per_group);
}

static struct directories_t * readdir_inode(int inode) {
	struct directories_t * dir_result = malloc(sizeof(struct directories_t));

	struct blk_t *blocks = addr_inode_data(inode);

	if (blocks == NULL) {
		show_inode(inode);
		return NULL;
	}

	int addr_debut = blocks->addr;

	struct ext2_directory *dir = malloc(sizeof(struct ext2_directory));
	pread(fd, dir, sizeof(struct ext2_directory), addr_debut);
	dir_result->dir = dir;
	dir_result->next = NULL;

	int cur_pos = addr_debut;
	while (dir->rec_len + cur_pos < addr_debut + (1024 << superblock.s_log_block_size)) {
		cur_pos += dir->rec_len;
		dir = malloc(sizeof(struct ext2_directory));
		pread(fd, dir, sizeof(struct ext2_directory), cur_pos);
		struct directories_t *element = malloc(sizeof(struct directories_t));
		element->dir = dir;
		element->next = dir_result;
		dir_result = element;
	}

	return dir_result;
}

static int getinode_from_path2(const char *path, int current_inode) {
	while (*path == '/') path++;
	if (*path == '\0') {
		return current_inode;
	}

	struct directories_t *dirs = readdir_inode(current_inode);
	struct directories_t *aux = dirs;
	char *s = strchrnul(path, '/');
	while (aux != NULL) {
		aux->dir->name[aux->dir->name_len] = '\0';
		if (strncmp(path, aux->dir->name, s - path) == 0 && (s - path) == (aux->dir->name_len)) {
			if (*s == '\0' || aux->dir->file_type & EXT2_FT_DIR) {
				return getinode_from_path2(s, aux->dir->inode);
			} else {
				return -ENOTDIR;
			}
		}
		aux = aux->next;
	}
	return -ENOENT;
}

static int getinode_from_path(const char *path) {
	return getinode_from_path2(path, EXT2_ROOT_INO);
}

static int read_inode(int inode, struct ext2_inode* einode) {
	if (inode > 0) {
		int i = inode - 1;
		int n = i / superblock.s_inodes_per_group;
		int ib = i % superblock.s_inodes_per_group;
		
		int addr_bitmap = group_desc_table[n].bg_inode_bitmap;
		int addr_table = group_desc_table[n].bg_inode_table;
		uint8_t inode_bitmap;
		
		pread(fd, &inode_bitmap, 1, addr_bitmap * (1024 << superblock.s_log_block_size) + ib / 8);
	
		if (inode_bitmap & (1 << (ib % 8))) {
			pread(fd, einode, sizeof(struct ext2_inode), addr_table * (1024 << superblock.s_log_block_size) + sizeof(struct ext2_inode) * ib);
			return 0;
		}
	}
	return -ENOENT;
}

static int write_inode(int inode, struct ext2_inode* einode) {
	if (inode > 0) {
		int i = inode - 1;
		int n = i / superblock.s_inodes_per_group;
		int ib = i % superblock.s_inodes_per_group;
		
		int addr_table = group_desc_table[n].bg_inode_table;
		
		pwrite(fd, einode, sizeof(struct ext2_inode), addr_table * (1024 << superblock.s_log_block_size) + sizeof(struct ext2_inode) * ib);
		return 0;
	}
	return -ENOENT;
}


static struct blk_t* read_indirect_blk(struct blk_t* blocks, int addr) {
	int j;
	uint32_t *addrs = malloc(1024 << superblock.s_log_block_size);
	pread(fd, addrs, 1024 << superblock.s_log_block_size, addr * (1024 << superblock.s_log_block_size));
	for (j = 0; j < (1024 << superblock.s_log_block_size) / 4 && addrs[j]; j++) {
		struct blk_t* element = malloc(sizeof(struct blk_t));
		element->next = NULL;
		element->addr = addrs[j] * (1024 << superblock.s_log_block_size);
		blocks->next = element;
		blocks = element;
	}
	return blocks;
}

static struct blk_t* read_double_indirect_blk(struct blk_t* blocks, int addr) {
	int j;
	uint32_t *addrs = malloc(1024 << superblock.s_log_block_size);
	pread(fd, addrs, 1024 << superblock.s_log_block_size, addr * (1024 << superblock.s_log_block_size));
	for (j = 0; j < (1024 << superblock.s_log_block_size) / 4 && addrs[j]; j++) {
		blocks = read_indirect_blk(blocks, addrs[j]);
	}
	return blocks;
}

static struct blk_t* read_triple_indirect_blk(struct blk_t* blocks, int addr) {
	int j;
	uint32_t *addrs = malloc(1024 << superblock.s_log_block_size);
	pread(fd, addrs, 1024 << superblock.s_log_block_size, addr * (1024 << superblock.s_log_block_size));
	for (j = 0; j < (1024 << superblock.s_log_block_size) / 4 && addrs[j]; j++) {
		blocks = read_double_indirect_blk(blocks, addrs[j]);
	}
	return blocks;
}


static void update_blocks(struct ext2_inode* einode, struct blk_t *blocks) {
	int i = 0;
	int block_size = (1024 << superblock.s_log_block_size);
	while (blocks) {
		if (i < 12) {
			einode->i_block[i] = blocks->addr / block_size;
		} else if (i >= 12 && i < 12 + block_size / 4) {
			if (einode->i_block[12] == 0) {
				einode->i_block[12] = alloc_block();
				uint8_t zeros[1024];
				memset(zeros, 0, sizeof(zeros));
				int j;
				for (j = 0; j < (1 << superblock.s_log_block_size); j++) {
					pwrite(fd, zeros, block_size, einode->i_block[12] * block_size + j * 1024);
				}
			}
			uint32_t addr = blocks->addr / block_size;
			pwrite(fd, &addr, 4, einode->i_block[12] * block_size + (i - 12) * 4); 
		} else if (i >= 12 + block_size / 4 && i < 12 + (block_size / 4) * (block_size / 4)) {
			if (einode->i_block[13] == 0) {
				einode->i_block[13] = alloc_block();
			}
			//TODO!
		} else {
			if (einode->i_block[14] == 0) {
				einode->i_block[14] = alloc_block();
			}
			//TODO!
		}
		blocks = blocks->next;
		i++;
	}
	while (i < 12) {
		einode->i_block[i] = 0;
		i++;
	}
	// TODO!
}


static struct blk_t* addr_inode_data(int inode) {
	struct ext2_inode einode;
	if (read_inode(inode, &einode) >= 0) {
		struct blk_t *blocks = NULL;
		struct blk_t *last = NULL;
		int j;
		// direct blocks
		for (j = 0; j < 12 && einode.i_block[j]; j++) {
			struct blk_t* element = malloc(sizeof(struct blk_t));
			element->next = NULL;
			element->addr = einode.i_block[j] * (1024 << superblock.s_log_block_size);
			if (last == NULL) {
				blocks = element;
			} else {
				last->next = element;
			}
			last = element;
		}
		if (j == 12) {
			// indirect blocks
			if (einode.i_block[12]) {
				last = read_indirect_blk(last, einode.i_block[12]);
			}
			if (einode.i_block[13]) {
				last = read_double_indirect_blk(last, einode.i_block[13]);
			}
			if (einode.i_block[14]) {
				last = read_triple_indirect_blk(last, einode.i_block[14]);
			}
		}
		return blocks;
	}
	return NULL;
}

static void show_inode(int i) {
	fprintf(stderr, "@inode %d :\n", i);
	i -= 1;
	int n = i / superblock.s_inodes_per_group;
	int ib = i % superblock.s_inodes_per_group;
	
	int addr_bitmap = group_desc_table[n].bg_inode_bitmap;
	int addr_table = group_desc_table[n].bg_inode_table;
	uint8_t *inode_bitmap = malloc(1024 << superblock.s_log_block_size);
	struct ext2_inode *inode_table = malloc(sizeof(struct ext2_inode) * superblock.s_inodes_per_group);
	
	pread(fd, inode_bitmap, (1024 << superblock.s_log_block_size), addr_bitmap * (1024 << superblock.s_log_block_size));
	pread(fd, inode_table, sizeof(struct ext2_inode) * superblock.s_inodes_per_group, addr_table * (1024 << superblock.s_log_block_size));

	fprintf(stderr, "Utilisé : %s\n", (inode_bitmap[ib/8] & (1 << (ib % 8)) ? "oui" : "non"));
	fprintf(stderr, "size : %d\n", (inode_table[ib].i_size));
	fprintf(stderr, "blocks :\n");
	int j;
	for (j = 0; j < 15; j++) {
		fprintf(stderr, "%d ", inode_table[ib].i_block[j]);
	}
	fprintf(stderr, "\n");
}

static void read_group_desc_table() {
	int b = superblock.s_first_data_block + 1;
	n_groups = ceil((float)superblock.s_blocks_count / (float)superblock.s_blocks_per_group);
	group_desc_table = malloc(sizeof(struct ext2_group_desc) * n_groups);

	pread(fd, group_desc_table, sizeof(struct ext2_group_desc) * n_groups, b * (1024 << superblock.s_log_block_size));
}

static void getattr_inode(int inode, struct stat *stbuf) {
	struct ext2_inode einode;
	if (read_inode(inode, &einode) == 0) {
		stbuf->st_ino = inode + 1;
		stbuf->st_mode = einode.i_mode;
		stbuf->st_nlink = einode.i_links_count;
		stbuf->st_uid = einode.i_uid;
		stbuf->st_gid = einode.i_gid;
		stbuf->st_size = einode.i_size;
		stbuf->st_blksize = 1024 << superblock.s_log_block_size;
		stbuf->st_blocks = einode.i_size / 512;
		stbuf->st_atime = einode.i_atime;
		stbuf->st_mtime = einode.i_mtime;
		stbuf->st_ctime = einode.i_ctime;
	}
}

static void setattr_inode(int inode, struct stat *stbuf) {
	struct ext2_inode einode;
	if (read_inode(inode, &einode) == 0) {
		einode.i_mode = stbuf->st_mode;
		einode.i_uid = stbuf->st_uid;
		einode.i_gid = stbuf->st_gid;
		einode.i_atime = stbuf->st_atime;
		einode.i_mtime = stbuf->st_mtime;
		struct timeval tv;
		gettimeofday(&tv, NULL);
		einode.i_ctime = tv.tv_sec;
		write_inode(inode, &einode);
	}
}

static uint32_t alloc_block() {
	int i;
	for (i = 0; i < n_groups; i++) {
		if (group_desc_table[i].bg_free_blocks_count) {
			// TODO: decrement bg_free_blocks_count
			int addr_bitmap = group_desc_table[i].bg_block_bitmap;
			uint8_t *block_bitmap = malloc(1024 << superblock.s_log_block_size);
			pread(fd, block_bitmap, (1024 << superblock.s_log_block_size), addr_bitmap * (1024 << superblock.s_log_block_size));

			int ib;
			for (ib = 0; ib < superblock.s_blocks_per_group; ib++) {
				if ((block_bitmap[ib/8] & (1 << (ib % 8))) == 0) {
					block_bitmap[ib/8] |= (1 << (ib % 8));
					pwrite(fd, &(block_bitmap[ib/8]), sizeof(uint8_t), addr_bitmap * (1024 << superblock.s_log_block_size) + ib / 8);
					return ib + i * superblock.s_blocks_per_group;
				}
			}
		}
	}
	return 0;
}

static int alloc_inode(struct ext2_inode *inode) {
	int i;
	for (i = 0; i < n_groups; i++) {
		if (group_desc_table[i].bg_free_inodes_count) {
			// TODO: decrement bg_free_inodes_count
			int addr_bitmap = group_desc_table[i].bg_inode_bitmap;
			int addr_table = group_desc_table[i].bg_inode_table;
			uint8_t *inode_bitmap = malloc(1024 << superblock.s_log_block_size);
	
			pread(fd, inode_bitmap, (1024 << superblock.s_log_block_size), addr_bitmap * (1024 << superblock.s_log_block_size));

			int ib;
			for (ib = 0; ib < superblock.s_inodes_per_group; ib++) {
				int inode_n = i * superblock.s_inodes_per_group + ib + 1;
				if ((inode_bitmap[ib/8] & (1 << (ib % 8))) == 0) {
					pwrite(fd, inode, sizeof(struct ext2_inode), addr_table * (1024 << superblock.s_log_block_size) + sizeof(struct ext2_inode) * ib);
					inode_bitmap[ib/8] |= (1 << (ib % 8));
					pwrite(fd, &(inode_bitmap[ib/8]), sizeof(uint8_t), addr_bitmap * (1024 << superblock.s_log_block_size) + ib / 8);
					return inode_n;
				}
			}
		}
	}
	return 0;
}

static void add_dir_entry(int inode, const char *name, int type, int n_inode) {
	struct blk_t *blocks = addr_inode_data(inode);

	if (blocks == NULL) {
		// TODO: create block. Ne devrait pas arriver...
	}

	int addr_debut = blocks->addr;

	struct ext2_directory *dir = malloc(sizeof(struct ext2_directory));
	pread(fd, dir, sizeof(struct ext2_directory), addr_debut);

	int cur_pos = addr_debut;
	while (dir->rec_len + cur_pos < addr_debut + (1024 << superblock.s_log_block_size)) {
		cur_pos += dir->rec_len;
		pread(fd, dir, sizeof(struct ext2_directory), cur_pos);
	}

	int s = 4 + 2 + 1 + 1 + dir->name_len;
	s += (4 - (s % 4)) % 4;
	dir->rec_len = s;
	pwrite(fd, dir, s, cur_pos);
	cur_pos += s;
	
	struct ext2_directory ndir;
	ndir.inode = n_inode;
	ndir.rec_len = addr_debut + (1024 << superblock.s_log_block_size) - cur_pos;
	ndir.name_len = strlen(name);
	ndir.file_type = type;
	strcpy(ndir.name, name);
	int s2 = 4 + 2 + 1 + 1 + ndir.name_len;
	s2 += (4 - (s % 4)) % 4;
	pwrite(fd, &ndir, s2, cur_pos);
}

static void remove_dir_entry(int inode, const char *name) {
	struct blk_t *blocks = addr_inode_data(inode);

	if (blocks == NULL) {
		return;
	}

	int addr_debut = blocks->addr;

	struct ext2_directory dir, dir2;
	pread(fd, &dir, sizeof(struct ext2_directory), addr_debut);

	int cur_pos = addr_debut;
	int cur_pos2 = 0;
	int dec = 0;
	while (dir.rec_len + cur_pos < addr_debut + (1024 << superblock.s_log_block_size)) {
		dir.name[dir.name_len] = '\0';
		if (strcmp(name, dir.name) == 0) {
			dec = dir.rec_len;
		}

		cur_pos2 = cur_pos;
		cur_pos += dir.rec_len;
		dir2 = dir;
		pread(fd, &dir, sizeof(struct ext2_directory), cur_pos);
		if (dec > 0) {
			if (dir.rec_len + cur_pos >= addr_debut + (1024 << superblock.s_log_block_size)) {
				dir.rec_len += dec;
			}
			pwrite(fd, &dir, dir.rec_len, cur_pos - dec); //XXX
		}
	}

	if (dec == 0 && cur_pos2) {
		dir.name[dir.name_len] = '\0';
		if (strcmp(name, dir.name) == 0) {
			dir2.rec_len += dir.rec_len;
			pwrite(fd, &dir2, dir2.rec_len, cur_pos2); //XXX
		}
	}
}

static void mknod_inode(int inode, const char *name, mode_t mode, dev_t dev) {
	fprintf(stderr, "mknod_inode %s\n", name);
	struct ext2_inode n_inode;
	memset(&n_inode, 0, sizeof(struct ext2_inode));
	n_inode.i_mode = mode;
	n_inode.i_links_count = 1;
	struct fuse_context *fc = fuse_get_context();
	n_inode.i_uid = fc->uid;
	n_inode.i_gid = fc->gid;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	n_inode.i_atime = tv.tv_sec;
	n_inode.i_ctime = tv.tv_sec;
	n_inode.i_mtime = tv.tv_sec;
	
	add_dir_entry(inode, name, EXT2_FT_REG_FILE, alloc_inode(&n_inode));
}


static void init_dir(int inode, int parent_inode) {
	struct blk_t *blocks = addr_inode_data(inode);

	if (blocks == NULL) {
		return;
	}
	int addr = blocks->addr;
	struct ext2_directory dir;
	dir.inode = inode;
	dir.rec_len = 4 + 2 + 1 + 1 +1;
	dir.name_len = 1;
	dir.file_type = EXT2_FT_DIR;
	strcpy(dir.name, ".");

	pwrite(fd, &dir, sizeof(dir), addr);
	addr += dir.rec_len;

	dir.inode =	parent_inode;
	dir.rec_len = (1024 << superblock.s_log_block_size) - addr;
	dir.name_len = 2;
	dir.file_type = EXT2_FT_DIR;
	strcpy(dir.name, "..");
	pwrite(fd, &dir, sizeof(dir), addr);
}

static void mkdir_inode(int inode, const char *name, mode_t mode) {
	struct ext2_inode n_inode;
	memset(&n_inode, 0, sizeof(struct ext2_inode));
	n_inode.i_mode = mode | EXT2_S_IFDIR;
	n_inode.i_links_count = 2;
	struct fuse_context *fc = fuse_get_context();
	n_inode.i_uid = fc->uid;
	n_inode.i_gid = fc->gid;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	n_inode.i_atime = tv.tv_sec;
	n_inode.i_ctime = tv.tv_sec;
	n_inode.i_mtime = tv.tv_sec;
	int ninode = alloc_inode(&n_inode);
	add_dir_entry(inode, name, EXT2_FT_DIR, ninode);

	init_dir(ninode, inode);
}

static void mount_ext2() {
 	fprintf(stderr, "Mount EXT2.\n");

	fd = open(options.device, O_RDWR);
 	if (fd > 0) {
		pread(fd, &superblock, sizeof(superblock), 1024);
		read_group_desc_table();
		show_info();
	}	else {
		exit(1);
	}
}

static int ext2_utimens(const char *path, const struct timespec tv[2]) {
	int inode = getinode_from_path(path);
	if (inode >= 0) {
		struct stat s;
		getattr_inode(inode, &s);
		s.st_atime = tv[0].tv_sec;
		s.st_mtime = tv[1].tv_sec;
		setattr_inode(inode, &s);
		return 0;
	} else {
		return inode;
	}
}

static int ext2_mkdir(const char * path, mode_t mode) {
	char filename[256];
  char * dir = malloc(strlen(path));
	split_dir_filename(path, dir, filename);

	int inode = getinode_from_path(dir);
	if (inode >= 0) {
		mkdir_inode(inode, filename, mode);
		return 0;
	} else {
		return inode;
	}
}

static int ext2_getattr(const char *path, struct stat *stbuf) {
	int inode = getinode_from_path(path);
	if (inode >= 0) {
		getattr_inode(inode, stbuf);
		return 0;
	} else {
		return inode;
	}
}

static int ext2_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi) {
	char name[256];
	int inode = getinode_from_path(path);
	if (inode >= 0) {
		struct directories_t *dirs = readdir_inode(inode);
		struct directories_t *aux = dirs;
		while (aux != NULL) {
			strncpy(name, aux->dir->name, aux->dir->name_len);
			name[aux->dir->name_len] = '\0';
			filler(buf, name, NULL, 0);
			aux = aux->next;
		}
		return 0;
	} else {
		return inode;
	}
}

static int ext2_open(const char *path, struct fuse_file_info *fi) {
	fprintf(stderr, "open %s\n", path);
	int inode = getinode_from_path(path);
	if (inode == -ENOENT && (fi->flags & O_CREAT)) {
		//XXX
		ext2_mknod(path, 00644 | 0x8000, 0);
	} else if (inode <= 0) {
		return inode;
	} else if (fi->flags & O_EXCL && fi->flags & O_CREAT) {
		return -EEXIST;
	}

	return 0;
}

static int ext2_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
	fprintf(stderr, "open %s, flags : %x\n", path, fi->flags);
	int inode = getinode_from_path(path);
	if (inode >= 0) {
		int count = 0;
		struct ext2_inode einode;
		read_inode(inode, &einode);
		
		if (offset >= einode.i_size) {
			return 0;
		}

		if (size + offset > einode.i_size) {
			size = einode.i_size - offset;
		}

		struct blk_t *blocks = addr_inode_data(inode);
		if (blocks == NULL) return 0;
		while (offset >= 1024 << superblock.s_log_block_size) {
			if (blocks && blocks->next) {
				blocks = blocks->next;
			} else return 0;
			offset -= 1024 << superblock.s_log_block_size;
		}


		while (size > 0 && blocks != NULL) {
			int addr = blocks->addr + offset;
			int size2 = (1024 << superblock.s_log_block_size) - offset;
			offset = 0;
			if (size2 > size) {
				size2 = size;
			}

			pread(fd, buf + count, size2, addr);
			size -= size2;
			count += size2;

			blocks = blocks->next;
		}

		// Commenté pour des raisons évidentes de perf.
		//	struct timeval tv;
		//	gettimeofday(&tv, NULL);
		//	einode.i_atime = tv.tv_sec;
		//	write_inode(inode, &einode);
		return count;
	} else {
		return inode;
	}
}

static int ext2_write (const char *path, const char *buf, size_t size, off_t offset,
                       struct fuse_file_info *fi) {
	fprintf(stderr, "write %s, flags : %x, size: %d\n", path, fi->flags, (int)size);
	int inode = getinode_from_path(path);
	if (inode >= 0) {
		struct ext2_inode einode;
		if (read_inode(inode, &einode) == 0) {
			int count = 0;
			struct blk_t *last = NULL;
			struct blk_t *blocks = addr_inode_data(inode);
			struct blk_t *aux = blocks;

			int off = offset;
			while (aux != NULL && off >= (1024 << superblock.s_log_block_size)) {
				last = aux;
				aux = aux->next;
				off -= 1024 << superblock.s_log_block_size;
			}

			while (size > 0) {
				if (aux == NULL) {
					struct blk_t *element = malloc(sizeof(struct blk_t));
					element->addr = alloc_block() * (1024 << superblock.s_log_block_size);
					element->next = NULL;
					if (last == NULL) {
						blocks = element;
					} else {
						last->next = element;
					}
					aux = element;
				}
				int addr = aux->addr + off;
				int size2 = (1024 << superblock.s_log_block_size) - off;
				off = 0;
				if (size2 > size) {
					size2 = size;
				}

				pwrite(fd, buf + count, size2, addr);
				size -= size2;
				count += size2;

				last = aux;
				aux = aux->next;
			}

			einode.i_size = max(einode.i_size, offset + count);
			struct timeval tv;
			gettimeofday(&tv, NULL);
			einode.i_mtime = tv.tv_sec;
			update_blocks(&einode, blocks);
			write_inode(inode, &einode);
			return count;		
		} else {
			return -ENOENT;
		}
		return size;
	} else {
		return inode;
	}
}

static int ext2_mknod(const char * path, mode_t mode, dev_t dev) {
	char filename[256];
  char * dir = malloc(strlen(path));
	split_dir_filename(path, dir, filename);

	int inode = getinode_from_path(dir);
	if (inode >= 0) {
		mknod_inode(inode, filename, mode, dev);
		return 0;
	}

	return -ENOENT;
}

static int ext2_chmod(const char * path, mode_t mode) {
	int inode = getinode_from_path(path);
	if (inode >= 0) {
		struct stat s;
		getattr_inode(inode, &s);
		s.st_mode = mode;
		setattr_inode(inode, &s);
		return 0;
	} else {
		return inode;
	}
}

static int ext2_chown(const char * path, uid_t uid, gid_t gid) {
	int inode = getinode_from_path(path);
	if (inode >= 0) {
		struct stat s;
		getattr_inode(inode, &s);
		s.st_uid = uid;
		s.st_gid = gid;
		setattr_inode(inode, &s);
		return 0;
	} else {
		return inode;
	}
}

static int ext2_truncate(const char * path, off_t off) {
	int inode = getinode_from_path(path);
	fprintf(stderr, "truncate inode %d (%s) : %d\n", inode, path, (int)off);
	return 0;
}

static int ext2_unlink(const char * path) {
	int inode = getinode_from_path(path);
	if (inode > 0) {
		char filename[256];
		char * dir = malloc(strlen(path));
		split_dir_filename(path, dir, filename);
		inode = getinode_from_path(dir);
		// TODO: Check is regular file.
		remove_dir_entry(inode, filename);
		// Free !
		return 0;
	} else {
		return inode;
	}
}

static int ext2_rmdir(const char * path) {
	int inode = getinode_from_path(path);
	if (inode > 0) {
		char filename[256];
		char * dir = malloc(strlen(path));
		split_dir_filename(path, dir, filename);
		inode = getinode_from_path(dir);
		// TODO: Check is dir.
		// TODO: Call rmdir_inode!
		remove_dir_entry(inode, filename);
		// Free !
		return 0;
	} else {
		return inode;
	}
}

static int ext2_rename(const char *orig, const char *dest) {
	fprintf(stderr, "mv %s %s\n", orig, dest);
	int inode = getinode_from_path(orig);
	if (inode > 0) {
		// Get parent dir.
		char filename[256];
		char * dir = malloc(strlen(orig));
		split_dir_filename(orig, dir, filename);
		int dir_inode = getinode_from_path(dir);

		// Remove inode from parent dir.
		remove_dir_entry(dir_inode, filename);

		// Add inode to dest.
		dir = malloc(strlen(dest));
		split_dir_filename(dest, dir, filename);
		int dest_inode = getinode_from_path(dir);
		add_dir_entry(dest_inode, filename, EXT2_FT_REG_FILE, inode);
		return 0;
	} else {
		return inode;
	}
}

static struct fuse_operations ext2_oper = {
		.chmod = ext2_chmod,
		.chown = ext2_chown,
		.mknod = ext2_mknod,
		.getattr = ext2_getattr,
		.mkdir = ext2_mkdir,
		.open = ext2_open,
		.read = ext2_read,
		.readdir = ext2_readdir,
		.truncate = ext2_truncate,
		.utimens = ext2_utimens,
		.write = ext2_write,
		.unlink = ext2_unlink,
		.rmdir = ext2_rmdir,
		.rename = ext2_rename,
};

int main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct ext2_state *ext2_data = NULL;
	
	if (fuse_opt_parse(&args, &options, ext2_fuse_opts, NULL) == -1)
		return -1; /** error parsing **/
	
	fprintf(stderr, "device : %s\n", options.device);
	
	debug = fopen("/tmp/debugfuse", "w+");
	mount_ext2();
	
	ret = fuse_main(args.argc, args.argv, &ext2_oper, ext2_data);
	fuse_opt_free_args(&args);

	return ret;
}

