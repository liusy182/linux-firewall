typedef enum {
	NOOP, IN, OUT, DEL, PRINT
}Operation;

typedef enum {
	NOPROTOCOL, ALL, UDP, TCP, ICMP
}Protocol;

typedef enum {
	NOACTION, BLOCK, UNBLOCK
}Action;

typedef struct {
	unsigned char seg1;
	unsigned char seg2;
	unsigned char seg3;
	unsigned char seg4;
}IP;

struct PolicyCache {
    Operation operation;
    int index; // delete index, set when operation == DEL
    IP srcip;
    IP srcnetmask;
    unsigned int srcport;
    IP destip;
    IP destnetmask;
    unsigned int destport;
    Protocol proto;
    Action action;
    struct PolicyCache* next;
};
