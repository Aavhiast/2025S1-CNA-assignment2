#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

/* ------------------------------------------------------------------ */
/* STUB OUT THE missing nsimmax for local Stop-and-Wait emulator:     */
/* this definition is weak so the autograder’s emulator.c will override it */
/* ------------------------------------------------------------------ */
#ifdef __GNUC__
__attribute__((weak)) int nsimmax = 0;
#else
int nsimmax = 0;
#endif

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
#define SEQSPACE 12     /* 2 * Windowsize */
#define NOTINUSE (-1)   /* used to fill header fields that are not being used */

int ComputeChecksum(struct pkt packet) {
  int i;
  int checksum = packet.seqnum + packet.acknum;
  for (i = 0; i < 20; i++)
    checksum += (int)(packet.payload[i]);
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

void A_output(struct msg message) {
  struct pkt sendpkt;
  int i;

  if ((nextseqnum - base + SEQSPACE) % SEQSPACE < WINDOWSIZE) {
    if (TRACE > 1)
      printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");

    sendpkt.seqnum = nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++)
      sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    buffer[nextseqnum] = sendpkt;
    used[nextseqnum] = true;
    acked[nextseqnum] = false;

    if (TRACE > 0)
      printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3(A, sendpkt);

    if (base == nextseqnum)
      starttimer(A, RTT);

    nextseqnum = (nextseqnum + 1) % SEQSPACE;
  } else {
    if (TRACE > 0)
      printf("----A: New message arrives, send window is full\n");
    window_full++;
  }
}

void A_input(struct pkt packet) {
  int ack = packet.acknum;

  if (!IsCorrupted(packet) && used[ack] && !acked[ack]) {
    if (TRACE > 0)
      printf("----A: uncorrupted ACK %d is received\n", ack);
    total_ACKs_received++;

    if (TRACE > 0)
      printf("----A: ACK %d is not a duplicate\n", ack);
    new_ACKs++;
    acked[ack] = true;

    if (ack == base) {
      while (acked[base]) {
        used[base] = false;
        acked[base] = false;
        base = (base + 1) % SEQSPACE;
      }
      stoptimer(A);
      if (base != nextseqnum)
        starttimer(A, RTT);
    }
  }
  else if (!IsCorrupted(packet) && used[ack] && acked[ack]) {
    if (TRACE > 0)
      printf("----A: duplicate ACK received, do nothing!\n");
  }
  else {
    if (TRACE > 0)
      printf("----A: corrupted ACK is received, do nothing!\n");
  }
}

void A_timerinterrupt(void) {
  if (TRACE > 0)
    printf("----A: time out,resend packets!\n");

  if (used[base] && !acked[base]) {
    if (TRACE > 0)
      printf("---A: resending packet %d\n", buffer[base].seqnum);
    tolayer3(A, buffer[base]);
    packets_resent++;
  }

  starttimer(A, RTT);
}

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
static bool received[SEQSPACE];           /* Mark if packet with seqnum was received */
static int expected_base;                 /* Lowest seqnum not yet delivered to layer 5 */

void B_input(struct pkt packet) {
  struct pkt ackpkt;
  int i, seq = packet.seqnum;
  int window_end = (expected_base + WINDOWSIZE) % SEQSPACE;
  bool in_window = (expected_base <= window_end)
                     ? (seq >= expected_base && seq < window_end)
                     : (seq >= expected_base || seq < window_end);

  if (!IsCorrupted(packet) && in_window) {
    if (TRACE > 0)
      printf("----B: packet %d is correctly received, send ACK!\n", seq);
    packets_received++;

    if (!received[seq]) {
      recv_buffer[seq] = packet;
      received[seq] = true;
      while (received[expected_base]) {
        tolayer5(B, recv_buffer[expected_base].payload);
        received[expected_base] = false;
        expected_base = (expected_base + 1) % SEQSPACE;
      }
    }
    ackpkt.acknum = seq;
  }
  else {
    if (TRACE > 0)
      printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
    ackpkt.acknum = (expected_base == 0 ? SEQSPACE - 1 : expected_base - 1);
  }

  ackpkt.seqnum = 0;
  for (i = 0; i < 20; i++)
    ackpkt.payload[i] = '0';
  ackpkt.checksum = ComputeChecksum(ackpkt);
  tolayer3(B, ackpkt);
}

void B_init(void) {
  int i;
  expected_base = 0;
  for (i = 0; i < SEQSPACE; i++)
    received[i] = false;
}

void B_output(struct msg message) {}
void B_timerinterrupt(void) {}
