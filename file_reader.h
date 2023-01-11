#ifndef FILE_SYSTEM_FAT12_FILE_READER_H
#define FILE_SYSTEM_FAT12_FILE_READER_H

#include <stdint.h>

struct clusters_chain_t {
    uint16_t *clusters;
    size_t size;
};

struct creation_time_t
{
    uint8_t second:5;
    uint8_t minute:6;
    uint8_t hour:5;
} __attribute__((__packed__));

struct creation_date_t
{
    uint8_t day:5;
    uint8_t month:4;
    uint8_t year:7;
} __attribute__((__packed__));

struct attributes_t
{
    unsigned char bit_0:1;
    unsigned char bit_1:1;
    unsigned char bit_2:1;
    unsigned char bit_3:1;
    unsigned char bit_4:1;
    unsigned char bit_5:1;
    unsigned char bit_6:1;
    unsigned char bit_7:1;
};

struct dir_entry_full_t
{
    char name[11];
    struct attributes_t attributes;
    uint8_t reserved;
    uint8_t creation_time_tenths;
    struct creation_time_t creation_time;
    struct creation_date_t creation_date;
    struct creation_date_t last_access_date;
    uint16_t first_cluster_high;
    struct creation_time_t last_modification_time;
    struct creation_date_t last_modification_date;
    uint16_t first_cluster_low;
    uint32_t file_size;
} __attribute__((__packed__));

struct boot_sector_t
{
    char jump_instruction[3];
    uint64_t oem_name;
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t sectors_reserved_area;
    uint8_t fats_number;
    uint16_t root_directory_max_files;
    uint16_t sectors_number;
    uint8_t media_type;
    uint16_t size_of_each_fat;
    uint16_t sectors_per_track;
    uint16_t heads_number;
    uint32_t sectors_number_before_start;
    uint32_t sectors_number_file_system;
    uint8_t drive_number;
    uint8_t not_used_byte;
    uint8_t extended_boot_signature;
    uint32_t volume_serial_number;
    char volume_label[11];
    uint64_t file_system_type;
    char not_used_bytes[448];
    uint16_t signature_value;
} __attribute__((__packed__));

struct disk_t
{
    FILE *fd;
    const char *filename;
} __attribute__((__packed__));

struct volume_t
{
    struct disk_t *pdisk;
    struct boot_sector_t boot_sector;
    void *primary_fat;
    void *secondary_fat;
    uint32_t first_root_sector;
    uint32_t root_sector_count;
    void *root_directory_entries;
} __attribute__((__packed__));

struct dir_t
{
    struct volume_t *pvolume;
    int32_t read_count;
} __attribute__((__packed__));

struct dir_entry_t
{
    char name[13];
    unsigned int size;
    unsigned char is_archived:1;
    unsigned char is_readonly:1;
    unsigned char is_system:1;
    unsigned char is_hidden:1;
    unsigned char is_directory:1;
    uint16_t first_cluster;
} __attribute__((__packed__));

struct file_t
{
    struct volume_t *pvolume;
    struct dir_entry_t file_entry;
    int32_t offset;
    struct clusters_chain_t *file_clusters;
    struct dir_t *file_directory;
} __attribute__((__packed__));

struct disk_t* disk_open_from_file(const char* volume_file_name);
int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read);
int disk_close(struct disk_t* pdisk);

struct volume_t* fat_open(struct disk_t* pdisk, uint32_t first_sector);
int fat_close(struct volume_t* pvolume);
int compare_fats(void *fat1, void *fat2, size_t size_of_each_fat);
void parse_name(const char *source, char *destination, unsigned char is_directory);

struct file_t* file_open(struct volume_t* pvolume, const char* file_name);
int file_close(struct file_t* stream);
size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream);
int32_t file_seek(struct file_t* stream, int32_t offset, int whence);

struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path);
int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry);
int dir_close(struct dir_t* pdir);

struct clusters_chain_t *get_chain_fat12(const void * const buffer, size_t size, uint16_t first_cluster);
int filenamecmp(const char *fn1, const char *fn2);

#endif
