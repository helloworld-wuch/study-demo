
SOURCE = $(wildcard ./inflate.c)     #获取所有的.c文件  
OBJ = $(patsubst %.c, %.o, $(SOURCE))   #将.c文件转为.o文件  

LIB_PATH = -lz

TARGET = inflate


$(TARGET): $(OBJ)     
	gcc $(OBJ) $(LIB_PATH) -o $(TARGET)
 
%.o: %.c  
	gcc -Wall -c $< -o $@  
 
.PHONY: clean  
clean:  
	rm -rf $(OBJ) $(TARGET)
