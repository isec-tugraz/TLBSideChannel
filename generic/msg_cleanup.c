#include "msg_msg.h"

int main(void)
{
    printf("[*] cleanup\n");
    for (size_t i = 0; i < (1<<24); ++i)
        msgctl(i, IPC_RMID, 0);
}