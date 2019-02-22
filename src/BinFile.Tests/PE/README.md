#include <stdio.h>


int add(int a, int b) {
  int count;
  if (a < b) {
    count = a;
  }
  else {
    count = b;
  }

  for (int i = 1; i < count + 1; i++)
    a = a + 1;
  return a;
}

int sub(int a, int b) {
  for (int i = 1; i < b + 1; i++)
    a = a - 1;
  return a;
}

int mul(int a, int b) {
  int c = 0;
  for (int i = 1; i < b + 1; i++)
    c = c + a;
  return c;
}

int div(int a, int b) {
  int c = a / b;
  return c;
}

int calc(int a, int b) {
  int result;
  for (int i = 0; i < 4; i++)
  {
    switch (i) {
    case 0 :
      result = add(a, b);
      printf("%d + %d = %d\n", a, b, result);
      break;
    case 1:
      result = sub(a, b);
      printf("%d - %d = %d\n", a, b, result);
      break;
    case 2:
      result = mul(a, b);
      printf("%d * %d = %d\n", a, b, result);
      break;
    case 3:
      result = div(a, b);
      printf("%d / %d = %d\n", a, b, result);
      break;
    }
  }
  return 0;
}

int main()
{
  int a, b;
  printf("insert number: \n");
  scanf_s("%d", &a);
  printf("insert number: \n");
  scanf_s("%d", &b);

  calc(a, b);

  return 0;
}

