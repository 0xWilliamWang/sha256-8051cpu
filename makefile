.RECIPEPREFIX = >

test:
> $(CC) test.c sha256.c -ansi -g -o $@.out
> ./$@.out

clean:
> rm *.out *.exe
