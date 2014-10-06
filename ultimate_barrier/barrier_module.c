
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/file.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/fcntl.h>
#include <linux/highmem.h>
#include <linux/ipc_namespace.h>
#include <asm/io.h>
#include <linux/ipc.h>
#include <linux/slab.h>
#include <linux/fsnotify.h>
#include <linux/fdtable.h>
#include <linux/string.h>

#define __SMP__
#define __NR_GET_BARRIER		 314
#define __NR_RELEASE_BARRIER	 317
#define __NR_SLEEP_ON_BARRIER    315
#define __NR_AWAKE_ON_BARRIER	 316
#define NUMBER_OF_TAGS		     32
#define SIZE_OF_BARRIER 		 32 * sizeof(wait_queue_head_t)
#define MAX_PARALLELS_BAR		 5
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Palamaro");
MODULE_DESCRIPTION("OS2 thesis");

// to wait if we are using all the barriers availables 
struct semaphore sem_to_create_barrier;

// for the association key -> descriptor
atomic64_t *barrierID_key;

// sem for each barrier
struct semaphore *sem_array;

// array of barriers with displacement = descriptor
wait_queue_head_t **barriers;

extern void *sys_call_table[];

asmlinkage int (*original_call) (key_t,int);
asmlinkage int (*original_release)(int);
asmlinkage int (*original_sleep_on_barrier)(int,int);
asmlinkage int (*original_awake_on_barrier)(int,int);

int verifyIfKeyPresent(key_t key){
	int i;
	for (i=0;i<MAX_PARALLELS_BAR;i++){
		if (atomic64_read(&barrierID_key[i]) == key){
			return i;
		}
	}
	return -1;
}
int getTheFirstFreeDescriptorAndSet(key_t key){
	int fd,i;
	for (i=0;i<MAX_PARALLELS_BAR;i++){
			if(atomic64_read(&barrierID_key[i])==0){
				fd = i;
				atomic64_set(&barrierID_key[i],key);
				return fd;
			}
	}
	return -1;
}

void installABarrierWithThisDescriptor(int fd){
	int i;
	wait_queue_head_t *my_array_pointer = (wait_queue_head_t*)kmalloc(SIZE_OF_BARRIER,GFP_KERNEL);
	for (i=0;i<NUMBER_OF_TAGS;i++){
			init_waitqueue_head((my_array_pointer+i));
		}	
	barriers[fd] = my_array_pointer;
}
	
asmlinkage int our_sys_get_barrier(key_t key,int flags){
	
	int temp_fd,fd=-1;
	mm_segment_t fs=get_fs();
	set_fs(KERNEL_DS);
	printk("Hello process with pid %d you are in get Barrier method \n",current->pid);
	temp_fd = verifyIfKeyPresent(key);
	if ((flags & 1<<9)!=0 && (flags & 1<<10)!=0){ // the flag IPC_CREAT|EXCL is up
		
		if(temp_fd != -1){
			printk(KERN_ERR"You want the excl creation but already exist \n");
			goto error;
		}
		down_interruptible(&sem_to_create_barrier);
		fd = getTheFirstFreeDescriptorAndSet(key);
		// now fd rapresent the index 
		installABarrierWithThisDescriptor(fd);
		sema_init((sem_array+fd),99);
		printk ("Now the semaphore is free and 99 users can access at same time\n");  
		goto exit;

	}else if ((flags & 1<<9)!=0 && (flags & 1<<10)==0){ // only IPC_CREAT is up
		
		if(temp_fd!=-1){
			printk(KERN_WARNING"The barrier already exist simply return the descriptor \n");
			fd = temp_fd;
			goto exit;
		}
		else{ // we must creat it
			down_interruptible(&sem_to_create_barrier);
			fd = getTheFirstFreeDescriptorAndSet(key);
			// now fd rapresent the index 
			installABarrierWithThisDescriptor(fd);
			sema_init((sem_array+fd),99);
			printk ("Now the semaphore is free and 99 users can read the memory at same time\n");  
			goto exit;
		}
	}	
	else{ // READER CASE
		printk("this is the reader...simply returns the descriptor of barrier \n");
		if (temp_fd == -1){
			printk("You want read a barrier that doesn't exist \n");
			goto error;
		}
		fd = temp_fd;
		goto exit;
	}
error:
	set_fs(fs);
	return -1;
exit:
	set_fs(fs);
	return fd;
}

asmlinkage int our_release_barrier(int bd)
{
	int i;
	//wait_queue_head_t *queue;
	mm_segment_t fs=get_fs();
	set_fs(KERNEL_DS);
	printk ("Hello process %d you are releasing the barrier with id %d \n",current->pid,bd);
	if (bd < 0 || bd > MAX_PARALLELS_BAR){
		printk("Descriptor out of range...\n");
		set_fs(fs);
		return -1;
	}
	if (atomic64_read(&barrierID_key[bd])==0){
		printk("This barrier is already released \n");
		set_fs(fs);
		return 0;
	}
	// GET THE SEM
	down_interruptible((sem_array+bd));
	// WAKE ALL THE PROCESSES
	printk ("Wake all the process before release the barrier \n");
	for (i=0;i<NUMBER_OF_TAGS;i++){
		wake_up_interruptible(&barriers[bd][i]);
	}
	printk("Done. Reset all control structures \n");
	atomic64_set(&barrierID_key[bd],0);
	kfree(barriers[bd]);
	sema_init((sem_array+bd),0);
	up(&sem_to_create_barrier);
	printk ("Done.Barrier released \n");	
	set_fs(fs);
	return 0;
}

asmlinkage int our_awake_on_barrier(int bd,int tag){
	mm_segment_t fs=get_fs();
	set_fs(KERNEL_DS);
	printk ("**AWAKE ON BARRIER-----Parameters BARRIED_ID:%d,TAG:%d \n",bd,tag);
	if (tag <0 || tag >=32 ){
		printk("Error when using the tag \n try with another value \n");
		goto error;
	}
	down_interruptible((sem_array+bd));
	wake_up_interruptible(&barriers[bd][tag]);
	printk ("Done.We have awaking processes \n");
	goto exit;
error:
	up((sem_array+bd));
	set_fs(fs);
	return -1;
exit:
	up((sem_array+bd));
	set_fs(fs);
	return 0;
}
asmlinkage int our_sleep_on_barrier(int bd,int tag){
	
	mm_segment_t fs=get_fs();
	set_fs(KERNEL_DS);
	printk ("The process with pid %d has required to sleep on barrier %d,with tag %d\n",current->pid,bd,tag);
	if (tag <0 || tag >=32 || bd <0 || bd > MAX_PARALLELS_BAR ){
		printk("Error when using the tag...try with another value \n");
		goto error;
	}
	// bd and tag correct
	down_interruptible((sem_array+bd));
	printk ("We now try to sleeping on this barrier\n");
	interruptible_sleep_on(&barriers[bd][tag]);
	goto exit;	
error:
	up((sem_array+bd));
	set_fs(fs);
	return -1;
	
exit:
	up((sem_array+bd));
	set_fs(fs);
	printk("Done.Exiting from sleep \n");
	return 0;
}
static void disable_page_protection(void) 
{
  unsigned long value;
  asm volatile("mov %%cr0, %0" : "=r" (value));

  if(!(value & 0x00010000))
    return;

  asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

static void enable_page_protection(void) 
{
  unsigned long value;
  asm volatile("mov %%cr0, %0" : "=r" (value));

  if((value & 0x00010000))
    return;

  asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}
static int mod_init(void)
{
	int i;
	printk("Backup previuous syscall\n");
	original_call=sys_call_table[__NR_GET_BARRIER];
	original_release=sys_call_table[__NR_RELEASE_BARRIER];
	original_sleep_on_barrier=sys_call_table[__NR_SLEEP_ON_BARRIER];
	original_awake_on_barrier = sys_call_table[__NR_AWAKE_ON_BARRIER];
	disable_page_protection();
	
	sys_call_table[__NR_GET_BARRIER] = our_sys_get_barrier;
	sys_call_table[__NR_RELEASE_BARRIER] = our_release_barrier;
	sys_call_table[__NR_SLEEP_ON_BARRIER]= our_sleep_on_barrier;
	sys_call_table[__NR_AWAKE_ON_BARRIER]= our_awake_on_barrier;
	enable_page_protection();
	printk ("Init sem array with vectors associated \n");
	sem_array = (struct semaphore*) kmalloc(MAX_PARALLELS_BAR*sizeof(struct semaphore),GFP_KERNEL);
	barrierID_key = (atomic64_t*) kmalloc(MAX_PARALLELS_BAR*sizeof(atomic64_t),GFP_KERNEL);
	barriers = kmalloc(MAX_PARALLELS_BAR*sizeof(wait_queue_head_t*),GFP_KERNEL);
	for (i=0;i<MAX_PARALLELS_BAR;i++){
		
		struct semaphore temp_sem;
		sema_init(&temp_sem,0);
		sem_array[i] = temp_sem;
		atomic64_set(&barrierID_key[i],0);
		barriers[i] = NULL;
	}
	printk("Init module Done....All structures initialized \n");
	sema_init(&sem_to_create_barrier,MAX_PARALLELS_BAR);
	return 0;

}
static void mod_exit(void)
{
	printk(KERN_INFO "stub module shutdown\n") ;
	printk("Restore old syscall \n");
	disable_page_protection();
	sys_call_table[__NR_GET_BARRIER]=original_call;
	sys_call_table[__NR_RELEASE_BARRIER]=original_release;
	sys_call_table[__NR_SLEEP_ON_BARRIER]=original_sleep_on_barrier;
	sys_call_table[__NR_AWAKE_ON_BARRIER]=original_awake_on_barrier;
	enable_page_protection();
	kfree(sem_array);
	kfree(barrierID_key);
	kfree(barriers);
	printk("Exiting \n");
}


module_init(mod_init);
module_exit(mod_exit);

