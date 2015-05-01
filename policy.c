//Assignment 3
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include "datatype.h"

void WriteToProc(struct PolicyCache *polityPtr)
{
    printf("in WriteToProc()..\n");
    FILE *pFile = fopen("/proc/firewall_sy", "wb");
    if (pFile == NULL)
    {
        printf("open /proc/firewall_sy for writing failed..\n");
    }
    else
    {
        if(fwrite(polityPtr, sizeof(struct PolicyCache), 1, pFile) != 1)
        {
            printf("WriteToProc(): fwrite failed..\n");
        }
        fclose(pFile);
    }
}
 
void PrintPolicies()
{
    printf("in PrintPolicies()..\n");
    FILE *pFile = fopen("/proc/firewall_sy", "rb");
    if (pFile == NULL)
    {
        printf("open /proc/firewall_sy for reading failed..\n");
    }
    else
    {   
        struct PolicyCache* item;
        int i = 1;
        do
        {   
            item = (struct PolicyCache*) malloc(sizeof(struct PolicyCache));
		    if(fread(item, sizeof(struct PolicyCache), 1, pFile) != 1)
		    {
                printf("PrintPolicies(): read to the end of file..\n");
                break;
            }
		    if(item != NULL && (item->operation == IN || item->operation == OUT))
		    {
	    	    printf("================Policy %d================\n", i);
	    	    char* inOut;
	    	    if(item->operation == IN)
	    	    {
	    	        printf("in/out: IN\n");
	    	    }
	    	    else if(item->operation == OUT)
	    	    {
	    	        printf("in/out: OUT\n");
	    	    }
	    	    
	    	    printf("srcip: %hhu.%hhu.%hhu.%hhu\n", (item->srcip).seg4, (item->srcip).seg3, (item->srcip).seg2, (item->srcip).seg1);
	    	    printf("srcport: %u\n", item->srcport);
	    	    printf("srcnetmask: %hhu.%hhu.%hhu.%hhu\n", (item->srcnetmask).seg4, (item->srcnetmask).seg3, (item->srcnetmask).seg2, (item->srcnetmask).seg1);
	    	    
	    	    printf("destip: %hhu.%hhu.%hhu.%hhu\n", (item->destip).seg4, (item->destip).seg3, (item->destip).seg2, (item->destip).seg1);
	    	    printf("destport: %u\n", item->destport);
                printf("destnetmask: %hhu.%hhu.%hhu.%hhu\n", (item->destnetmask).seg4, (item->destnetmask).seg3, (item->destnetmask).seg2, (item->destnetmask).seg1);
	    	    
	    	    if(item->proto == ALL)
                {
                    printf("protocol: ALL\n");
                }
                else if(item->proto == UDP)
                {
	    		    printf("protocol: UDP\n");
                }
                else if(item->proto == TCP)
                {
                    printf("protocol: TCP\n");
                }
                else if(item->proto == ICMP)
                {
                    printf("protocol: ICMP\n");
                }
	    			
	    		if(item->action == BLOCK)
                {
                    printf("action: BLOCK\n");
                }
                else if(item->action == UNBLOCK)
                {
	    		    printf("action: UNBLOCK\n");
                }
    		    printf("============End of Policy %d============\n", i);
		    }
		    i++;
		} while(item->next != NULL);
		fclose(pFile);
    }
}

IP ConvertIP(char *input)
{
    IP ipAddr;
	sscanf(input, "%hhu.%hhu.%hhu.%hhu", &ipAddr.seg4, &ipAddr.seg3, &ipAddr.seg2, &ipAddr.seg1);
	return ipAddr;
}

int main(int argc, char *argv[])
{
    struct PolicyCache policyCache;
    policyCache.operation = NOOP; 
    policyCache.index = -1;
    policyCache.srcip.seg1 = 0;
    policyCache.srcip.seg2 = 0; 
    policyCache.srcip.seg3 = 0; 
    policyCache.srcip.seg4 = 0; 
    policyCache.srcport = 0;
    policyCache.srcnetmask.seg1 = 0; 
    policyCache.srcnetmask.seg2 = 0; 
    policyCache.srcnetmask.seg3 = 0; 
    policyCache.srcnetmask.seg4 = 0; 
    policyCache.destip.seg1 = 0; 
    policyCache.destip.seg2 = 0; 
    policyCache.destip.seg3 = 0; 
    policyCache.destip.seg4 = 0; 
    policyCache.destport = 0;
    policyCache.destnetmask.seg1 = 0; 
    policyCache.destnetmask.seg2 = 0; 
    policyCache.destnetmask.seg3 = 0; 
    policyCache.destnetmask.seg4 = 0; 
    policyCache.proto = NOPROTOCOL;
    policyCache.action = NOACTION;
    policyCache.next = NULL;
    
    int c;
    while (1) 
    {
        static struct option long_options[] = 
        {
			{ "in", no_argument, 0, 'a' },
			{ "out", no_argument, 0, 'b' },
			{ "print", no_argument, 0, 'c' },
			{ "delete", required_argument, 0, 'd' },
			{ "srcip", required_argument, 0, 'e' },
			{ "srcport", required_argument, 0, 'f' },
			{ "srcnetmask",	required_argument, 0, 'g' },
			{ "destip", required_argument, 0, 'h' },
			{ "destport", required_argument, 0, 'i' },
			{ "destnetmask", required_argument, 0, 'j' },
			{ "action", required_argument, 0, 'k' },
			{ "proto", required_argument, 0, 'l' },
            {0, 0, 0, 0}
        };
        int option_index = 0;
        const char* const short_options = "abcd:e:f:g:h:i:j:k:l:";
        c = getopt_long(argc, argv, short_options, long_options, &option_index);
        if (c == -1)
            break;
        
        switch (c)
        {   
            case 'a': // --in
                policyCache.operation = IN;
                break;
            case 'b': // --out
                policyCache.operation = OUT;
                break;
			case 'c': // --print
				policyCache.operation = PRINT;
				break;
            case 'd': // --delete
                policyCache.operation = DEL;
                policyCache.index = atoi(optarg);
                break;
            case 'e': //srcip
                policyCache.srcip = ConvertIP(optarg);  
                break; 
            case 'f': //srcport
                policyCache.srcport = atoi(optarg);    
                break;
            case 'g': //srcnetmask
                policyCache.srcnetmask = ConvertIP(optarg); 
                break;
            case 'h': //destip
                policyCache.destip = ConvertIP(optarg);     
                break;
            case 'i': //destport
               policyCache.destport = atoi(optarg);    
               break;
            case 'j': //destnetmask
                policyCache.destnetmask = ConvertIP(optarg);    
                break;
            case 'k': //action
                if(strcmp ("BLOCK", optarg) == 0)
                {
					policyCache.action = BLOCK;
				}
				else if(strcmp ("UNBLOCK", optarg)==0)
				{
					policyCache.action = UNBLOCK;
				}
				break;
            case 'l': //proto
                if(strcmp ("ALL", optarg) == 0)
                {
					policyCache.proto = ALL;
				}
				else if(strcmp ("UDP", optarg)==0)
				{
					policyCache.proto = UDP;
				}
				else if(strcmp ("TCP", optarg)==0)
				{
					policyCache.proto = TCP;
				}
				else if(strcmp ("ICMP", optarg)==0)
				{
					policyCache.proto = ICMP;
				}
                break;
            default:
                break;
        } // end of switch    
    } //end of while
    
    if (policyCache.operation == IN || policyCache.operation == OUT || policyCache.operation == DEL)
    {
        WriteToProc(&policyCache);
    } 
    else if (policyCache.operation == PRINT)
    {
        PrintPolicies();
    }

} // end of main

