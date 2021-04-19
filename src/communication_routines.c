#include <unistd.h>

#include <main.h>
#include <communication_routines.h>

RC_t send_icmp(int net_fd, struct pkt * send_pkt, struct sockaddr_in * addr,
		uint32_t * pkt_size)
	/* pkt_size is payload size (include icmphdr and PKT_STUFF_SIZE) */
{
	int send_cnt, attempt;
	PR_DEBUG("%s, pkt_size: %i\n", __func__, *pkt_size);
	for (attempt = ATTEMPT_CNT;;) {
		if ((send_cnt = sendto(net_fd, send_pkt, *pkt_size,
						0, (struct sockaddr *)addr,
						sizeof(struct sockaddr_in)))
				== -1) {
			perror("sendto");
			if (--attempt >= 0) {
				continue;
			} else {
				return ERROR;
			}
		}
		PR_DEBUG("%s, pkt_size: %i\n", __func__, *pkt_size);
		*pkt_size = send_cnt;
		return SUCCESS;
	}
}

uint16_t in_cksum(uint16_t * addr, size_t len)
{
	int nleft = len;
	int sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *)(&answer) += *(unsigned char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

void free_icmp_stuffs(IcmpStuff_t * stuffs)
{
	if (stuffs) {
		if (stuffs->buffer)
			free(stuffs->buffer);
		if (stuffs->rb)
			rb_del(stuffs->rb);
		if (stuffs->buffer)
			free(stuffs->buffer);
		if (stuffs->client_addr)
			free(stuffs->client_addr);
		if (stuffs->server_addr)
			free(stuffs->server_addr);
		if (stuffs->send_pkt)
			free(stuffs->send_pkt);
		if (stuffs->recv_pkt)
			free(stuffs->recv_pkt);
		free(stuffs);
	}
}

RC_t write_all(int fd, void *buf, int32_t n, int32_t * tot_write)
{
	/* n is size of buffer, tot_write is the number of bytes write */
	int32_t tot, c;
	for (tot = 0; tot < n;) {
		c = write(fd, (char *)buf + tot, n - tot);
		tot += c;
		if ((c == -1 || c == 0) && tot != n) {
			perror("write write_all");
			*tot_write = tot;
			return ERROR;
		}
	}
	*tot_write = tot;
	return SUCCESS;
}

RC_t read_all(int fd, void *buf, int32_t n, int32_t * tot_read)
{
	/* n is size of buffer, tot_read is the number of bytes read */
	int32_t tot, c;
	for (tot = 0; tot < n;) {
		c = read(fd, (char *)buf + tot, n - tot);
		tot += c;
		if ((c == -1 || c == 0) && tot != n) {
			perror("read read_all");
			*tot_read = tot;
			return ERROR;
		}
	}
	*tot_read = tot;
	return SUCCESS;
}
