#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "file_reader.h"

#define SECTOR_SIZE 512

struct disk_t* disk_open_from_file(const char* volume_file_name)
{
    if(!volume_file_name)
    {
        errno = EFAULT;
        return NULL;
    }

    FILE *fd = fopen(volume_file_name, "rb");
    if(!fd)
    {
        errno = ENOENT;
        return NULL;
    }

    struct disk_t *disk = (struct disk_t *) calloc(1, sizeof(struct disk_t));
    if(!disk)
    {
        errno = ENOMEM;
        fclose(fd);
        return NULL;
    }

    disk->fd = fd;
    disk->filename = volume_file_name;

    return disk;
}

int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read)
{
    if(!pdisk || !buffer)
    {
        errno = EFAULT;
        return -1;
    }

    fseek(pdisk->fd, first_sector * SECTOR_SIZE, SEEK_SET);

    size_t res;
    int j = 0;
    for(int i = first_sector; i < (first_sector + sectors_to_read); ++i)
    {
        res = fread(((char *)buffer + j * SECTOR_SIZE), SECTOR_SIZE, 1, pdisk->fd);
        if(res < 1)
        {
            errno = ERANGE;
            return -1;
        }
        ++j;
    }

    return sectors_to_read;
}

int disk_close(struct disk_t* pdisk)
{
    if(!pdisk)
    {
        errno = EFAULT;
        return -1;
    }

    fclose(pdisk->fd);
    free(pdisk);

    return 0;
}

struct volume_t* fat_open(struct disk_t* pdisk, uint32_t first_sector)
{
    if(!pdisk)
    {
        errno = EFAULT;
        return NULL;
    }

    struct volume_t *fat = (struct volume_t *) calloc(1, sizeof(struct volume_t));
    if(!fat)
    {
        errno = ENOMEM;
        return NULL;
    }

    fat->pdisk = pdisk;

    int res = disk_read(pdisk, (int32_t)first_sector, &fat->boot_sector, 1);
    if(res == -1 || fat->boot_sector.signature_value != 0xaa55)
    {
        errno = EINVAL;
        free(fat);
        return NULL;
    }

    fat->primary_fat = calloc(1, fat->boot_sector.bytes_per_sector * fat->boot_sector.size_of_each_fat);

    if(!fat->primary_fat)
    {
        errno = ENOMEM;
        free(fat);
        return NULL;
    }

    fat->secondary_fat = calloc(1, fat->boot_sector.bytes_per_sector * fat->boot_sector.size_of_each_fat);

    if(!fat->secondary_fat)
    {
        errno = ENOMEM;
        free(fat->primary_fat);
        free(fat);
        return NULL;
    }

    int res1 = disk_read(pdisk, (int32_t)fat->boot_sector.sectors_reserved_area, fat->primary_fat, fat->boot_sector.size_of_each_fat);
    int res2 = disk_read(pdisk, (int32_t)((int32_t)fat->boot_sector.sectors_reserved_area + fat->boot_sector.size_of_each_fat), fat->secondary_fat, fat->boot_sector.size_of_each_fat);

    if(res1 == -1 || res2 == -1)
    {
        errno = EINVAL;
        free(fat->secondary_fat);
        free(fat->primary_fat);
        free(fat);
        return NULL;
    }

    if(compare_fats(fat->primary_fat, fat->secondary_fat, fat->boot_sector.bytes_per_sector * fat->boot_sector.size_of_each_fat))
    {
        errno = EINVAL;
        free(fat->secondary_fat);
        free(fat->primary_fat);
        free(fat);
        return NULL;
    }

    int32_t root_dir_sectors = ((fat->boot_sector.root_directory_max_files * 32) + (fat->boot_sector.bytes_per_sector - 1)) / fat->boot_sector.bytes_per_sector;
    int32_t first_data_sector = fat->boot_sector.sectors_reserved_area + (fat->boot_sector.fats_number * fat->boot_sector.size_of_each_fat) + root_dir_sectors;

    int32_t first_root_dir_sector = first_data_sector - root_dir_sectors;

    fat->first_root_sector = first_root_dir_sector;
    fat->root_sector_count = root_dir_sectors;

    fat->root_directory_entries = calloc(1, fat->root_sector_count * fat->boot_sector.bytes_per_sector);
    if(!fat->root_directory_entries)
    {
        errno = ENOMEM;
        free(fat->secondary_fat);
        free(fat->primary_fat);
        free(fat);
        return NULL;
    }

    int res3 = disk_read(pdisk, first_root_dir_sector, fat->root_directory_entries, root_dir_sectors);
    if(res3 == -1)
    {
        errno = EINVAL;
        free(fat->root_directory_entries);
        free(fat->secondary_fat);
        free(fat->primary_fat);
        free(fat);
        return NULL;
    }

    return fat;
}

int compare_fats(void *fat1, void *fat2, size_t size_of_each_fat)
{
    if(!fat1 || !fat2)
    {
        return -1;
    }

    for(int i = 0; i < (int)size_of_each_fat; ++i)
    {
        if(*((char *)fat1 + i) != *((char *)fat2 + i))
        {
            return 1;
        }
    }

    return 0;
}

void parse_name(const char *source, char *destination, unsigned char is_directory)
{
    if(source && destination)
    {
        if(is_directory)
        {
            for(int i = 0; i < 11; ++i)
            {
                if(source[i] != ' ')
                {
                    destination[i] = source[i];
                }
            }
        }
        else
        {
            int i = 0;
            while(i < 8)
            {
                if(source[i] != ' ')
                {
                    destination[i] = source[i];
                }
                else
                {
                    break;
                }

                ++i;
            }

            if(source[8] != ' ')
            {
                destination[i++] = '.';
                for(int j = 8; j < 11; ++j)
                {
                    if(source[j] != ' ')
                    {
                        destination[i++] = source[j];
                    }
                }
            }
        }
    }
}

int fat_close(struct volume_t* pvolume)
{
    if(!pvolume)
    {
        errno = EFAULT;
        return -1;
    }

    free(pvolume->root_directory_entries);
    free(pvolume->secondary_fat);
    free(pvolume->primary_fat);
    free(pvolume);

    return 0;
}

struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path)
{
    if(!pvolume || !dir_path)
    {
        errno = EFAULT;
        return NULL;
    }

    if(strcmp(dir_path, "\\") != 0)
    {
        if(strcmp(dir_path, "/") != 0)
        {
            errno = ENOENT;
            return NULL;
        }
    }

    struct dir_t *directory = (struct dir_t *) calloc(1, sizeof(struct dir_t));
    if(!directory)
    {
        errno = ENOMEM;
        return NULL;
    }

    directory->pvolume = pvolume;

    return directory;
}

int dir_close(struct dir_t* pdir)
{
    if(!pdir)
    {
        errno = EFAULT;
        return -1;
    }

    free(pdir);

    return 0;
}

int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry)
{
    if(!pdir || !pentry)
    {
        errno = EFAULT;
        return -1;
    }

    memset(pentry, 0, sizeof(struct dir_entry_t));

    struct dir_entry_full_t *full_entry = ((struct dir_entry_full_t *)pdir->pvolume->root_directory_entries + pdir->read_count);

    if(full_entry->name[0] == 0x00)
    {
        return 1;
    }
    else if((uint8_t )full_entry->name[0] == 0xe5)
    {
        pdir->read_count++;
        return dir_read(pdir, pentry);
    }

    pentry->size = full_entry->file_size;
    pentry->is_archived = full_entry->attributes.bit_5;
    pentry->is_readonly = full_entry->attributes.bit_0;
    pentry->is_system = full_entry->attributes.bit_2;
    pentry->is_hidden = full_entry->attributes.bit_1;
    pentry->is_directory = full_entry->attributes.bit_4;
    pentry->first_cluster = full_entry->first_cluster_low;

    parse_name(full_entry->name, pentry->name, pentry->is_directory);

    pdir->read_count++;

    return 0;
}

struct file_t* file_open(struct volume_t* pvolume, const char* file_name)
{
    if(!pvolume || !file_name)
    {
        errno = EFAULT;
        return NULL;
    }

    struct file_t *file = (struct file_t *) calloc(1, sizeof(struct file_t));
    if(!file)
    {
        errno = ENOMEM;
        return NULL;
    }

    file->pvolume = pvolume;

    struct dir_t *directory = dir_open(pvolume, "\\");
    file->file_directory = directory;
    while(dir_read(directory, &file->file_entry) == 0)
    {
        if(filenamecmp(file_name, file->file_entry.name) == 0)
        {
            if(file->file_entry.is_directory)
            {
                errno = EISDIR;
                free(directory);
                free(file);
                return NULL;
            }
            file->file_clusters = get_chain_fat12(pvolume->primary_fat, pvolume->boot_sector.bytes_per_sector * pvolume->boot_sector.size_of_each_fat, file->file_entry.first_cluster);
            return file;
        }
    }

    dir_close(directory);
    free(file);

    return NULL;
}

int file_close(struct file_t* stream)
{
    if(!stream)
    {
        errno = EFAULT;
        return -1;
    }

    free(stream->file_clusters->clusters);
    free(stream->file_clusters);
    dir_close(stream->file_directory);
    free(stream);

    return 0;
}

size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream)
{
    if(!stream || !ptr)
    {
        errno = EFAULT;
        return -1;
    }

    size_t elements_count;
    size_t to_read;
    if(size * nmemb > stream->file_entry.size - stream->offset)
    {
        elements_count = (stream->file_entry.size - stream->offset)/size;
        to_read = stream->file_entry.size - stream->offset;
    }
    else
    {
        elements_count = nmemb;
        to_read = size * nmemb;
    }

    uint32_t first_data_sector = stream->pvolume->boot_sector.sectors_reserved_area + (stream->pvolume->boot_sector.fats_number * stream->pvolume->boot_sector.size_of_each_fat) + stream->pvolume->root_sector_count;
    void *buffer = calloc(stream->pvolume->boot_sector.bytes_per_sector, stream->pvolume->boot_sector.sectors_per_cluster);

    uint32_t total_read_bytes = 0, read_bytes;
    for(int i = 0; i < (int)stream->file_clusters->size; ++i)
    {
        if(!to_read)
        {
            break;
        }

        uint16_t cluster = stream->file_clusters->clusters[stream->offset/(stream->pvolume->boot_sector.bytes_per_sector * stream->pvolume->boot_sector.sectors_per_cluster)];
        uint32_t first_sector_of_cluster = ((cluster - 2) * stream->pvolume->boot_sector.sectors_per_cluster) + first_data_sector;

        disk_read(stream->pvolume->pdisk, (int32_t)first_sector_of_cluster, buffer, stream->pvolume->boot_sector.sectors_per_cluster);

        uint32_t cluster_offset = stream->offset%(stream->pvolume->boot_sector.bytes_per_sector * stream->pvolume->boot_sector.sectors_per_cluster);
        uint32_t cluster_left_bytes = (stream->pvolume->boot_sector.bytes_per_sector * stream->pvolume->boot_sector.sectors_per_cluster) - cluster_offset;

        if(to_read >= (stream->pvolume->boot_sector.bytes_per_sector * stream->pvolume->boot_sector.sectors_per_cluster))
        {
            memcpy((char *)ptr+total_read_bytes, (char *)buffer + cluster_offset, cluster_left_bytes);
            total_read_bytes += cluster_left_bytes;
            read_bytes = cluster_left_bytes;
            to_read -= cluster_left_bytes;
        }
        else
        {
            if(to_read > cluster_left_bytes)
            {
                memcpy((char *)ptr+total_read_bytes, (char *)buffer + cluster_offset, cluster_left_bytes);
                total_read_bytes += cluster_left_bytes;
                read_bytes = cluster_left_bytes;
                to_read -= cluster_left_bytes;
            }
            else
            {
                memcpy((char *)ptr+total_read_bytes, (char *)buffer + cluster_offset, to_read);
                total_read_bytes += to_read;
                read_bytes = to_read;
                to_read -= to_read;
            }
        }

        file_seek(stream, (int32_t)read_bytes, SEEK_CUR);
    }

    free(buffer);

    return elements_count;
}

int32_t file_seek(struct file_t* stream, int32_t offset, int whence)
{
    if(!stream)
    {
        errno = EFAULT;
        return -1;
    }

    switch (whence) {
        case SEEK_SET:
        {
            stream->offset = offset;
        }
            break;
        case SEEK_CUR:
        {
            stream->offset += offset;
        }
            break;
        case SEEK_END:
        {
            stream->offset = (int32_t)stream->file_entry.size + offset;
        }
            break;
        default:
        {
            errno = EINVAL;
            return -1;
        }
    }

    return 0;
}

struct clusters_chain_t *get_chain_fat12(const void * const buffer, size_t size, uint16_t first_cluster)
{
    if(!buffer || !size)
    {
        return NULL;
    }

    struct clusters_chain_t *clusters_chain = (struct clusters_chain_t *)calloc(1, sizeof(struct clusters_chain_t));
    if(!clusters_chain)
    {
        return NULL;
    }

    clusters_chain->size = 1;

    clusters_chain->clusters = (uint16_t *) calloc(clusters_chain->size, sizeof(uint16_t));
    if(!clusters_chain->clusters)
    {
        free(clusters_chain);
        return NULL;
    }

    uint16_t active_cluster = first_cluster;
    uint16_t fat_offset;
    uint16_t ent_offset;
    while(1)
    {
        fat_offset = active_cluster + (active_cluster / 2);
        ent_offset = fat_offset % size;

        uint16_t table_value = *(uint16_t *)((char *)buffer + ent_offset);

        if(active_cluster & 0x0001)
        {
            table_value = table_value >> 4;
        }
        else
        {
            table_value = table_value & 0x0FFF;
        }

        clusters_chain->clusters[clusters_chain->size - 1] = active_cluster;
        active_cluster = table_value;
        if(table_value >= 0xFF8)
        {
            break;
        }

        ++clusters_chain->size;
        uint16_t* new_table = (uint16_t *) realloc(clusters_chain->clusters, clusters_chain->size * sizeof(uint16_t));
        if(!new_table)
        {
            free(clusters_chain->clusters);
            free(clusters_chain);

            return NULL;
        }

        clusters_chain->clusters = new_table;
    }

    return clusters_chain;
}

int filenamecmp(const char *fn1, const char *fn2)
{
    int i = 0;
    while(fn1[i] != '\0' && fn1[i] != '.')
    {
        if(fn1[i] != fn2[i])
        {
            return 1;
        }

        ++i;
    }

    return 0;
}
