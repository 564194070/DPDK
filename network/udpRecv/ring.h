
#include <rte_ring.h>
#include <rte_malloc.h>
#include <string.h>


#define RING_SIZE	1024


struct inout_ring {

	struct rte_ring *in;
	struct rte_ring *out;
};

static struct inout_ring *rInst = NULL;

static struct inout_ring *ringInstance(void) {

	if (rInst == NULL) {

		rInst = (struct inout_ring*)rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
		memset(rInst, 0, sizeof(struct inout_ring));
	}
	return rInst;
}