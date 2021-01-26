.RECIPEPREFIX = >

test:
> $(CC) test.c sha256.c -g -o $@.out
> ./$@.out

clean:
> rm *.out *.exe
