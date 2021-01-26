.RECIPEPREFIX = >

test:
> $(CC) test.c sha256.c -ansi -g -o $@.out
> ./$@.out
> $(CC) test.c sha256.c -std=c89 -g -o $@.out
> ./$@.out
> $(CC) test.c sha256.c -std=c90 -g -o $@.out
> ./$@.out
> $(CC) test.c sha256.c -std=c99 -g -o $@.out
> ./$@.out
> $(CC) test.c sha256.c -std=c11 -g -o $@.out
> ./$@.out
> $(CC) test.c sha256.c -std=c17 -g -o $@.out
> ./$@.out
> $(CC) test.c sha256.c -std=c18 -g -o $@.out
> ./$@.out

clean:
> rm -f *.out *.exe
