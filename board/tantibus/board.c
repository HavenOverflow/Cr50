#include "common.h"
#include "hooks.h"
#include "signed_header.h"
#include "system.h"

/* Get header address of the backup RW copy. */
const struct SignedHeader *get_other_rw_addr(void)
{
	if (system_get_image_copy() == SYSTEM_IMAGE_RW)
		return (const struct SignedHeader *)
			get_program_memory_addr(SYSTEM_IMAGE_RW_B);

	return (const struct SignedHeader *)
		get_program_memory_addr(SYSTEM_IMAGE_RW);
}

/* Return true if the other RW is not ready to run. */
static int other_rw_is_inactive(void)
{
	const struct SignedHeader *header = get_other_rw_addr();

	return !!(header->image_size & TOP_IMAGE_SIZE_BIT);
}

static void board_init(void)
{

}

DECLARE_HOOK(HOOK_INIT, board_init, HOOK_PRIO_INIT_CR50_BOARD);