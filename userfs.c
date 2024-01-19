#include "userfs.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define min(a, b) ((a) < (b) ? (a) : (b))

enum {
	BLOCK_SIZE = 512,
	MAX_FILE_SIZE = 1024 * 1024 * 100,
};

/** Global error code. Set from any function on any error. */
static enum ufs_error_code ufs_error_code = UFS_ERR_NO_ERR;

struct block {
	/** Block memory. */
	char *memory;
	/** How many bytes are occupied. */
	int occupied;
	/** Next block in the file. */
	struct block *next;
	/** Previous block in the file. */
	struct block *prev;

	/* PUT HERE OTHER MEMBERS */
};

struct file {
	/** Double-linked list of file blocks. */
	struct block *block_list;
	/**
	 * Last block in the list above for fast access to the end
	 * of file.
	 */
	struct block *last_block;
	/** How many file descriptors are opened on the file. */
	int refs;
	/** File name. */
	char *name;
	/** Files are stored in a double-linked list. */
	struct file *next;
	struct file *prev;

	int deleted;
};

/** List of all files. */
static struct file *file_list = NULL;

struct filedesc {
	struct file *file;

	int flags;
	int bytes_position;
};

/**
 * An array of file descriptors. When a file descriptor is
 * created, its pointer drops here. When a file descriptor is
 * closed, its place in this array is set to NULL and can be
 * taken by next ufs_open() call.
 */
static struct filedesc **file_descriptors = NULL;
static int file_descriptor_count = 0;
static int file_descriptor_capacity = 0;

struct file *
create_new_file(const char *filename) {
    struct file *new_file = (struct file *)malloc(sizeof(struct file));
    if (!new_file) {
        return NULL;
    }

    new_file->name = strdup(filename);
    if (!new_file->name) {
        free(new_file);
        return NULL;
    }

    new_file->block_list = NULL;
    new_file->last_block = NULL;
    new_file->refs = 0;
    new_file->deleted = 0;

    // Insert new file at the beginning of the file list
    new_file->next = file_list;
    new_file->prev = NULL;
    if (file_list) {
        file_list->prev = new_file;
    }
    file_list = new_file;

    return new_file;
}


struct filedesc *
allocate_filedesc(struct file *file, int flags) {
    struct filedesc *fd = malloc(sizeof(struct filedesc));
    if (!fd) {
        return NULL;
    }

    fd->file = file;
    fd->flags = flags;
    fd->bytes_position = 0;

    return fd;
}

int 
add_filedesc_to_array(struct filedesc *fd) {
    if (file_descriptor_count == file_descriptor_capacity) {
        int new_capacity = file_descriptor_capacity == 0 ? 10 : file_descriptor_capacity * 2;
        struct filedesc **new_array = realloc(file_descriptors, new_capacity * sizeof(struct filedesc *));
        if (!new_array) {
            return -1;
        }
        file_descriptors = new_array;
        file_descriptor_capacity = new_capacity;

        for (int i = file_descriptor_count; i < new_capacity; i++) {
            file_descriptors[i] = NULL;
        }
    }

    for (int i = 0; i < file_descriptor_capacity; i++) {
        if (file_descriptors[i] == NULL) {
            file_descriptors[i] = fd;
            file_descriptor_count++;
            return i;
        }
    }

    // This should not happen, but just in case
    return -1;
}


enum ufs_error_code
ufs_errno()
{
	return ufs_error_code;
}

int 
ufs_open(const char *filename, int flags) {
    // Check if filename is NULL or empty
    if (!filename || *filename == '\0') {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    // Search for an existing file
    struct file *f = file_list;
    while (f) {
        if (strcmp(f->name, filename) == 0 && !f->deleted) {
            break;
        }
        f = f->next;
    }

    if (!f && (flags & UFS_CREATE)) {
        f = create_new_file(filename);
        if (!f) {
            ufs_error_code = UFS_ERR_NO_MEM;
            return -1;
        }
    } else if (!f) {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    struct filedesc *fd = allocate_filedesc(f, flags);
    if (!fd) {
        // Handle memory allocation failure
        ufs_error_code = UFS_ERR_NO_MEM;
        return -1;
    }

    // Find an empty spot in the file_descriptors array or expand it
    int fd_index = add_filedesc_to_array(fd);
    if (fd_index == -1) {
        free(fd);
        ufs_error_code = UFS_ERR_NO_MEM;
        return -1;
    }

    return fd_index;
}

struct block *
get_current_block(struct filedesc *fdesc) {
    if (!fdesc || !fdesc->file || !fdesc->file->block_list) {
        return NULL;
    }

    struct block *current = fdesc->file->block_list;
    int block_pos = 0;
    int block_number = fdesc->bytes_position / BLOCK_SIZE;

    while (block_pos < block_number && current) {
        current = current->next;
        block_pos++;
    }

    return current;
}

struct block *
allocate_new_block(struct file *file) {
    if (!file) {
        return NULL;
    }

    struct block *new_block = malloc(sizeof(struct block));
    if (!new_block) {
        return NULL;
    }

    new_block->memory = malloc(BLOCK_SIZE);
    if (!new_block->memory) {
        free(new_block);
        return NULL;
    }

    new_block->occupied = 0;
    new_block->next = NULL;
    new_block->prev = file->last_block;

    if (file->last_block) {
        file->last_block->next = new_block;
    } else {
        file->block_list = new_block;
    }

    file->last_block = new_block;

    return new_block;
}

ssize_t 
ufs_write(int fd, const char *buf, size_t size) {
    if (fd < 0 || fd >= file_descriptor_capacity || !file_descriptors[fd] || !buf || size == 0) {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    struct filedesc *fdesc = file_descriptors[fd];

    // Check if the file is deleted or not writable
    if (fdesc->file->deleted || fdesc->flags & UFS_READ_ONLY) {
        ufs_error_code = UFS_ERR_NO_PERMISSION;
        return -1;
    }

	if (fdesc->bytes_position + size > MAX_FILE_SIZE) {
		ufs_error_code = UFS_ERR_NO_MEM;
		return -1;
	}

    ssize_t total_written = 0;
    size_t to_write = size;
    struct block *current_block = get_current_block(fdesc);

    while (to_write > 0) {
        if (!current_block) {
            current_block = allocate_new_block(fdesc->file);
            if (!current_block) {
                ufs_error_code = UFS_ERR_NO_MEM;
                return -1;
            }
        }

        size_t write_size = min((size_t)BLOCK_SIZE - fdesc->bytes_position % BLOCK_SIZE, to_write);
        memcpy(current_block->memory + fdesc->bytes_position % BLOCK_SIZE, buf + total_written, write_size);
		int new_occupied = fdesc->bytes_position % BLOCK_SIZE + write_size;
		if (current_block->occupied < new_occupied) {
			current_block->occupied = new_occupied;
		}
		fdesc->bytes_position += write_size;
        total_written += write_size;
        to_write -= write_size;

        // Move to next block if needed
        if (current_block->occupied == BLOCK_SIZE) {
            current_block = current_block->next;
        }
    }

    return total_written;
}

ssize_t 
ufs_read(int fd, char *buf, size_t size) {
    if (fd < 0 || fd >= file_descriptor_capacity || !file_descriptors[fd] || !buf || size == 0) {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    struct filedesc *fdesc = file_descriptors[fd];

    if (fdesc->file->deleted || (fdesc->flags & UFS_WRITE_ONLY)) {
        ufs_error_code = UFS_ERR_NO_PERMISSION;
        return -1;
    }

    ssize_t total_read = 0;
    struct block *current_block = get_current_block(fdesc);

    while (size > 0 && current_block) {
        size_t available_to_read = min((size_t)current_block->occupied - fdesc->bytes_position % BLOCK_SIZE, size);
        
        memcpy(buf + total_read, current_block->memory + fdesc->bytes_position % BLOCK_SIZE, available_to_read);

		fdesc->bytes_position += available_to_read;
        total_read += available_to_read;
        size -= available_to_read;

        current_block = current_block->next;
    }

    return total_read;
}


void 
free_file_resources(struct file *file) {
    if (!file) {
        return;
    }

    struct block *current_block = file->block_list;
    while (current_block) {
        struct block *next_block = current_block->next;
        free(current_block->memory);
        free(current_block);
        current_block = next_block;
    }

    free(file->name);

    if (file->prev) {
        file->prev->next = file->next;
    } else {
        file_list = file->next;
    }
    if (file->next) {
        file->next->prev = file->prev;
    }

    free(file);
}

int 
ufs_close(int fd) {
    if (fd < 0 || fd >= file_descriptor_capacity || !file_descriptors[fd]) {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    struct file *file = file_descriptors[fd]->file;
    file->refs--;

    if (file->refs == 0 && file->deleted) {
        free_file_resources(file);
    }

    free(file_descriptors[fd]);
    file_descriptors[fd] = NULL;

    return 0;
}

int 
ufs_delete(const char *filename) {
    if (!filename || *filename == '\0') {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    struct file *current = file_list;
    while (current) {
        if (strcmp(current->name, filename) == 0) {
            current->deleted = 1;

            if (current->refs == 0) {
                free_file_resources(current);
            }

            return 0;
        }
        current = current->next;
    }

    ufs_error_code = UFS_ERR_NO_FILE;
    return -1;
}

void ufs_destroy(void) {
    while (file_list) {
        struct file *next_file = file_list->next;
        free_file_resources(file_list); // This frees the file and all its resources
        file_list = next_file;
    }

    for (int i = 0; i < file_descriptor_capacity; i++) {
        if (file_descriptors[i]) {
            free(file_descriptors[i]);
        }
    }

    free(file_descriptors);
    file_descriptors = NULL;
    file_descriptor_capacity = 0;
    file_descriptor_count = 0;
}


size_t get_file_size(struct file *file) {
    if (!file) {
        return 0;
    }

    size_t total_size = 0;
    struct block *current = file->block_list;
    while (current) {
        total_size += current->occupied;
        current = current->next;
    }

    return total_size;
}

int expand_file(struct file *file, size_t new_size) {
    if (!file) {
        return 0;
    }

    size_t current_size = get_file_size(file);
    while (current_size < new_size) {
        if (file->last_block == NULL || file->last_block->occupied == BLOCK_SIZE) {
            struct block *new_block = allocate_new_block(file);
            if (!new_block) {
                return 0;
            }
        } else {
            size_t available_space = BLOCK_SIZE - file->last_block->occupied;
            size_t size_to_add = min(available_space, new_size - current_size);
            file->last_block->occupied += size_to_add;
            current_size += size_to_add;
        }
    }

    return 1;
}

void shrink_file(struct file *file, size_t new_size) {
    if (!file) {
        return;
    }

    size_t current_size = get_file_size(file);
    while (current_size > new_size && file->block_list != NULL) {
        if (current_size - file->last_block->occupied < new_size) {
            size_t size_to_remove = current_size - new_size;
            file->last_block->occupied -= size_to_remove;
            break;
        } else {
            current_size -= file->last_block->occupied;
            struct block *to_remove = file->last_block;
            file->last_block = file->last_block->prev;

            if (file->last_block) {
                file->last_block->next = NULL;
            } else {
                file->block_list = NULL;
            }

            free(to_remove->memory);
            free(to_remove);
        }
    }
}

int 
ufs_resize(int fd, size_t new_size) {
    if (fd < 0 || fd >= file_descriptor_capacity || file_descriptors[fd] == NULL) {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    struct filedesc *fdesc = file_descriptors[fd];
    if (fdesc->flags & UFS_READ_ONLY) {
        ufs_error_code = UFS_ERR_NO_PERMISSION;
        return -1;
    }

    struct file *file = fdesc->file;
    size_t current_size = get_file_size(file);

    if (new_size > current_size) {
        if (!expand_file(file, new_size)) {
            ufs_error_code = UFS_ERR_NO_MEM;
            return -1;
        }
    } else if (new_size < current_size) {
        shrink_file(file, new_size);
    }

	for (int i = 0; i < file_descriptor_capacity; i++) {
		if (file_descriptors[i] != NULL && file_descriptors[i]->file == file) {
			if (file_descriptors[i]->bytes_position > (int)new_size) {
				file_descriptors[i]->bytes_position = new_size;
			}
		}
	}

    return 0;
}
