#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declarations
char *Read_File(const char *filename, int *length);
int Read_Int_From_File(const char *filename);
int Write_File(const char *filename, const char *data);
int Write_Int_To_File(const char *filename, int value);

int main(int argc, char *argv[])
{
    printf("Server is running...\n");

    int challenge_len;
    char *challenge_hex = Read_File(argv[1], &challenge_len);

    if (challenge_len <= 0)
    {
        fprintf(stderr, "Error: Failed to read challenge from file %s\n", argv[1]);
        return 1;
    }

    int k = Read_Int_From_File(argv[2]);

    if (Write_File("puzzle_challenge.txt", challenge_hex) != 0)
    {
        fprintf(stderr, "Error: Failed to write puzzle challenge to file\n");
        free(challenge_hex);
        return 1;
    }

    if (Write_Int_To_File("puzzle_k.txt", k) != 0)
    {
        fprintf(stderr, "Error: Failed to write puzzle k to file\n");
        free(challenge_hex);
        return 1;
    }

    free(challenge_hex);
    return 0;
}

// Read File
char *Read_File(const char *filename, int *length)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = (char *)malloc(file_size + 1);
    if (!buffer)
    {
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';

    // Remove trailing whitespace
    while (read_size > 0 && (buffer[read_size - 1] == '\n' ||
                             buffer[read_size - 1] == '\r' ||
                             buffer[read_size - 1] == ' '))
    {
        buffer[--read_size] = '\0';
    }

    *length = read_size;
    fclose(file);
    return buffer;
}

int Read_Int_From_File(const char *filename)
{
    int length;
    char *str = Read_File(filename, &length);
    if (!str)
        return -1;

    int value = atoi(str);
    free(str);
    return value;
}

int Write_File(const char *filename, const char *data)
{
    FILE *file = fopen(filename, "w");
    if (!file)
    {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }

    fprintf(file, "%s", data);
    fclose(file);
    return 0;
}

int Write_Int_To_File(const char *filename, int value)
{
    char buffer[32];
    sprintf(buffer, "%d", value);
    return Write_File(filename, buffer);
}