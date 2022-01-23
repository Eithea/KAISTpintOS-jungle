/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		/// 3-2
		// type에 따라 anon, file initializer로 uninit page를 생성
		struct page* page = (struct page*)malloc(sizeof(struct page));
		if (VM_TYPE(type) == VM_ANON)
		{
			uninit_new(page, upage, init, type, aux, anon_initializer);
		}
		else if (VM_TYPE(type) == VM_FILE)
		{
			uninit_new(page, upage, init, type, aux, file_backed_initializer);
        }
        page->writable = writable;
        // hex_dump(page->va, page->va, PGSIZE, true);
		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	// struct page *page = NULL;
	/* TODO: Fill this function. */
	/// 3-1
	// 새 페이지를 할당해 page.va에 인풋값 va 대입
	struct page* page = (struct page*)malloc(sizeof(struct page));
    struct hash_elem *e;
    page->va = pg_round_down(va);
	// 이로부터 hash_elem 스트럭쳐 e를 취하고 page free
	// e가 존재하면 e로부터 page를 취해 return, 없으면 return NULL
    e = hash_find(&spt->hashtable, &page->hash_elem);
    free(page);
	if (e == NULL)
	{
		return NULL;
	}
	return hash_entry(e, struct page, hash_elem);
	// return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	/// 3-1
	// hash_insert()로 spt.page_table 삽입 시도 후 성공여부 TF return
	if (!hash_insert(&spt->hashtable, &page->hash_elem))
	{
		succ = true;
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	// struct frame *frame = NULL;
	/* TODO: Fill this function. */
	/// 3-1
	// 새 프레임 할당해서 초기화 후 return
	struct frame *frame = (struct frame*)malloc(sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER);
    frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	// struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	/// 3-2
	// 커널을 침범했을때만 즉시 false하고, 나머지 케이스에 대해서는 fault 핸들링을 시도
	if (is_kernel_vaddr(addr))
	{
        return false;
	}
	// claim으로 해결되면 해결하고, 실패시 return False
    void *rsp_stack = is_kernel_vaddr(f->rsp) ? thread_current()->rsp_stack : f->rsp;
    if (not_present)
	{
		/// 3-3
		// 실패시 stack 확장 시도, 이것도 실패시 return False
        if (!vm_claim_page(addr))
		{
            // if (rsp_stack - 8 <= addr && USER_STACK - 0x100000 <= addr && addr <= USER_STACK)
			// {
            //     vm_stack_growth(thread_current()->stack_bottom - PGSIZE);
            //     return true;
            // }
            return false;
        }
        else
            return true;
    }
    return false;
	// return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	/// 3-1
	// curr의 spt에서 va에 해당하는 페이지 탐색
	// 있으면 do claim, 없으면 return false
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
	{
		return false;
	}

	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/// 3-1
	struct thread *curr = thread_current();
	bool succ = (pml4_get_page(curr->pml4, page->va) == NULL && pml4_set_page(curr->pml4, page->va, frame->kva, page->writable));
	if (!succ)
	{
        return false;
    }

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	/// 3-1
	// 해시테이블 초기화
	hash_init(&spt->hashtable, hash_f, less_f, NULL);
}

/// 3-1
// hash_entry로 page.hash_elem 필드로부터 page 포인터값 계산
// page 주소값으로부터 생성된 해시값을 리턴
unsigned hash_f(const struct hash_elem *p, void *aux UNUSED)
{
    const struct page *pp = hash_entry(p, struct page, hash_elem);
    return hash_bytes(&pp->va, sizeof pp->va);
}

/// 3-1
// 마찬가지로 hash_elem a, b로부터 각 page 포인터값 계산
// 두 page.vaddr의 크기(= 위치)를 비교
bool less_f(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    const struct page *pa = hash_entry(a, struct page, hash_elem);
    const struct page *pb = hash_entry(b, struct page, hash_elem);
    return pa->va < pb->va;
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
