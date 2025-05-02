#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

/* ******************************************************************
   Go Back N protocol.  Adapted from J.F.Kurose
   ALTERNATING BIT AND GO-BACK-N NETWORK EMULATOR: VERSION 1.2

   Network properties:
   - one way network delay averages five time units (longer if there
   are other messages in the channel for GBN), but can be larger
   - packets can be corrupted (either the header or the data portion)
   or lost, according to user-defined probabilities
   - packets will be delivered in the order in which they were sent
   (although some can be lost).

   Modifications:
   - removed bidirectional GBN code and other code not used by prac.
   - fixed C style to adhere to current programming style
   - added GBN implementation
**********************************************************************/

#define RTT  16.0       /* round trip time.  MUST BE SET TO 16.0 when submitting assignment */
#define WINDOWSIZE 6    /* the maximum number of buffered unacked packet
                          MUST BE SET TO 6 when submitting assignment */
#define SEQSPACE 12      /* 2 * Windowsize */
#define NOTINUSE (-1)   /* used to fill header fields that are not being used */

/* generic procedure to compute the checksum of a packet.  Used by both sender and receiver
   the simulator will overwrite part of your packet with 'z's.  It will not overwrite your
   original checksum.  This procedure must generate a different checksum to the original if
   the packet is corrupted.
*/

int ComputeChecksum(struct pkt packet) {
  int checksum = packet.seqnum + packet.acknum;
  int i;
  for (i = 0; i < 20; i++) checksum += (int)(packet.payload[i]);
  return checksum;
}

bool IsCorrupted(struct pkt packet) {
  return packet.checksum != ComputeChecksum(packet);
}

/********* Sender (A) Selective Repeat ************/
static struct pkt buffer[SEQSPACE];      /* Store packets which were sent but not been acknowledged */
static bool acked[SEQSPACE];             /* Record which packets have been ACKed */
static bool used[SEQSPACE];              /* Mark valid packets */
static int base;                         /* Minimum window number */
static int nextseqnum;                   /* Nextseqnum need to be sent */

/* called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message) {
  struct pkt sendpkt;
  int i;

  /* if send window is not full */
  if ((nextseqnum - base + SEQSPACE) % SEQSPACE < WINDOWSIZE) {
    if (TRACE > 1)
      printf("----A: New message arrives, send window is not full, send new message to layer3!\n");

    /* create packet */
    sendpkt.seqnum = nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++) sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    /* put packet in buffer */
    buffer[nextseqnum] = sendpkt;
    used[nextseqnum] = true;
    acked[nextseqnum] = false;

    /* send packet to layer 3 */
    if (TRACE > 0)
      printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3(A, sendpkt);

    /* start timer if first in window */
    if (base == nextseqnum)
      starttimer(A, RTT);

    /* increment next sequence number */
    nextseqnum = (nextseqnum + 1) % SEQSPACE;
  } else {
    if (TRACE > 0)
      printf("----A: New message arrives, send window is full\n");
    window_full++;
  }
}

/* called from layer 3, when a packet arrives for layer 4
   In this practical this will always be an ACK as B never sends data. */
void A_input(struct pkt packet) {
  /* if received ACK is not corrupted */
  if (!IsCorrupted(packet)) {
    if (TRACE > 0)
      printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
    total_ACKs_received++;

    int ack = packet.acknum;

    /* check if new ACK or duplicate */
    if (!acked[ack] && used[ack]) {
      if (TRACE > 0)
        printf("----A: ACK %d is not a duplicate\n", ack);
      new_ACKs++;
      acked[ack] = true;

      /* slide base forward as much as possible */
      while (acked[base]) {
        acked[base] = false;
        used[base] = false;
        base = (base + 1) % SEQSPACE;
      }

      /* restart timer if there are unacked packets */
      stoptimer(A);
      if (base != nextseqnum)
        starttimer(A, RTT);
    } else {
      if (TRACE > 0)
        printf("----A: duplicate ACK received, do nothing!\n");
    }
  } else {
    if (TRACE > 0)
      printf("----A: corrupted ACK is received, do nothing!\n");
  }
}

/* called when A's timer goes off */
void A_timerinterrupt(void) {
  int i, oldest = -1;
  if (TRACE > 0)
    printf("----A: time out, selectively resend oldest unacked packet!\n");

  for (i = 0; i < SEQSPACE; i++) {
    if (used[i] && !acked[i]) {
      oldest = i;
      break;
    }
  }

  if (oldest != -1) {
    if (TRACE > 0)
      printf("---A: resending packet %d\n", buffer[oldest].seqnum);
    tolayer3(A, buffer[oldest]);
    packets_resent++;
  }

  starttimer(A, RTT);
}

/* the following routine will be called once (only) before any other */
/* entity A routines are called. You can use it to do any initialization */
void A_init(void) {
  int i;
  base = 0;
  nextseqnum = 0;
  for (i = 0; i < SEQSPACE; i++) {
    acked[i] = false;
    used[i] = false;
  }
}

/********* Receiver (B)  variables and procedures ************/

static struct pkt recv_buffer[SEQSPACE];  /* Receiver packet buffer */
static bool received[SEQSPACE];          /* Mark if packet with seqnum was received */
static int expected_base;                /* Lowest seqnum not yet delivered to layer 5 */

/* called from layer 3, when a packet arrives for layer 4 at B*/
void B_input(struct pkt packet) {
  struct pkt ackpkt;
  int i;

  /* if not corrupted */
  if (!IsCorrupted(packet)) {
    if (TRACE > 0)
      printf("----B: packet %d correctly received\n", packet.seqnum);
    packets_received++;

    int seq = packet.seqnum;

    /* if packet is within receiving window */
    int window_end = (expected_base + WINDOWSIZE) % SEQSPACE;
    bool in_window = (expected_base <= window_end) ?
                     (seq >= expected_base && seq < window_end) :
                     (seq >= expected_base || seq < window_end);

    if (in_window) {
      if (!received[seq]) {
        recv_buffer[seq] = packet;
        received[seq] = true;
      }

      /* deliver all in-order packets to application */
      while (received[expected_base]) {
        tolayer5(B, recv_buffer[expected_base].payload);
        if (TRACE > 0)
          /* printf("----B: delivered packet %d to application\n", expected_base); */
        received[expected_base] = false;
        expected_base = (expected_base + 1) % SEQSPACE;
      }
    }

    /* send ACK */
    ackpkt.seqnum = 0;  /* not used */
    ackpkt.acknum = seq;
    for (i = 0; i < 20; i++) ackpkt.payload[i] = '0';
    ackpkt.checksum = ComputeChecksum(ackpkt);
    tolayer3(B, ackpkt);
  } else {
    if (TRACE > 0)
      printf("----B: corrupted packet received, discard\n");
  }
}

/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init(void) {
  int i;
  expected_base = 0;
  for (i = 0; i < SEQSPACE; i++) received[i] = false;
}

/******************************************************************************
 * The following functions need be completed only for bi-directional messages *
 *****************************************************************************/

void B_output(struct msg message) {}
void B_timerinterrupt(void) {}
