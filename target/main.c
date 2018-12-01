#include <stdio.h>

int main() {
  int n;
  printf("NODE 1\n");

label1:
  printf("NODE 2\n");
  scanf("%d", &n);

  if (n == 1) {
label2:
    printf("NODE 3\n");

    scanf("%d", &n);
    if (n == 1) {
      printf("NODE 5\n");

      scanf("%d", &n);
      if (n == 1) {
        printf("NODE 7\n");
        goto label2;
      } else {
        printf("NODE 8\n");
      }
    } else {
      printf("NODE 6\n");

      scanf("%d", &n);
      if (n == 1) {
        printf("NODE 9\n");
      } else {
        printf("NODE 10\n");
      }

    }
  } else {
    printf("NODE 4\n");
    goto label1;
  }

  printf("NODE 11\n");

  return 0;
}
