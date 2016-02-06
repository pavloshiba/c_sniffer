#include "sniff.h"

int main(int argc,char **argv)
{
    char *devname;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
    pcap_if_t *alldevs, *device;
    char dev_buff[64] = {0};

    // Check if sufficient arguments were supplied
    if(argc != 3)
    {
        printf("\nUsage: %s [filter_expr][number-of-packets]\n",argv[0]);
        return 0;
    }

    char devs[100][100];
    int count = 1 , n;

    //First get the list of available devices
    printf("Finding available devices ... ");

    if( pcap_findalldevs( &alldevs , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done.");

    //Print the available devices
    printf("\nAvailable Devices are :\n");

    for(device = alldevs ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }

    //Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
    devname = devs[n];

    if(strlen(dev_buff))
    {
        devname = dev_buff;
        printf("\n ---You opted for device [%s] to capture [%d] packets---\n\n Starting capture...",devname, (atoi)(argv[2]));
    }

    if(devname == NULL)
    {
        printf("\n[%s]\n", errbuf);
        return -1;
    }

    logfile=fopen("log.txt","w");

    if(logfile == NULL )
    {
        printf("Unable to create file.");
    }

    // fetch the network address and network mask
    pcap_lookupnet(devname, &pNet, &pMask, errbuf);

    // Now, open device for sniffing
    descr = pcap_open_live(devname, BUFSIZ, 0,-1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    // Compile the filter expression
    if(pcap_compile(descr, &fp, argv[1], 0, pNet) == -1)
    {
        printf("\npcap_compile() failed\n");
        return -1;
    }

    // Set the filter compiled above
    if(pcap_setfilter(descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    pcap_loop(descr,atoi(argv[2]), callback, NULL);

    printf("\nDone with packet sniffing!\n");
    return 0;
}
