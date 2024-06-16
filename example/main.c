#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    printf("The PID of this process is: %d\n", getpid());
    // This pointer will hold the
    // base address of the block created
    int* ptr;
    int n, i;
 
    // Get the number of elements for the array
    n = 5;
 
    // Dynamically allocate memory using malloc()
    ptr = (int*)malloc(n * sizeof(int));
 
    // Check if the memory has been successfully
    // allocated by malloc or not
    if (ptr == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }
    else {
        while(1){
        // Memory has been successfully allocated
        printf("Memory successfully allocated using malloc.\n");
        int * mallocptr = (int*)malloc(n * sizeof(int));
        int * callocptr = (int*)calloc(n ,sizeof(int));

        // Get the elements of the array
        for (i = 0; i < n; ++i) {
            ptr[i] = i + 1;
        }
 
        // Print the elements of the array
        printf("The elements of the array are: ");
        for (i = 0; i < n; ++i) {
            printf("%d, ", ptr[i]);
        }
        n+=5;
        ptr = (int*)realloc(ptr,n * sizeof(int));
        sleep(1);
        if(n==100){
            free(ptr);
            break;
        }
    }
    }
 
    return 0;
}