# File system FAT12
## Description
FAT12 file reader project for educational purpose :open_book:. Contains only reading files from root directory. This project is not free from bugs so take note of it.
## Author
[@Blindeen](https://www.github.com/Blindeen)
## Usage
```c
#include <stdio.h>

#include "file_reader.h"

int main() {
    struct disk_t* disk = disk_open_from_file("fat12_volume.img");
    if (disk == NULL)
    {
        printf("Image opening error");
        return 1;
    }

    struct volume_t* volume = fat_open(disk, 0);
    if (volume == NULL)
    {
        disk_close(disk);
        printf("Image contains corrupted FAT table");
        return 2;
    }

    struct file_t* file = file_open(volume, "example.txt");
    if (file == NULL)
    {
        fat_close(volume);
        disk_close(disk);
        printf("File doesn't exist in root directory");
        return 3;
    }

    char buffer[1000] = {0};
    size_t read_bytes = file_read(buffer, 1, 999, file);
    if(read_bytes < 999)
    {
        file_close(file);
        fat_close(volume);
        disk_close(disk);
        printf("Data can't be fully read");
        return 4;
    }
    
    printf("File content:\n%s\n", buffer);

    file_close(file);
    fat_close(volume);
    disk_close(disk);
    return 0;
}
```
