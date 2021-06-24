# Vitrual Kernel Debug Util (VKDBG)

## General purpose

This utility is intended for assisting in kernel/kernel module development and debugging. The main purpose is routine automation like VM management, migration, processing, and so on. 

## Before you start

1. This util is currently in development and is used only for work purposes, therefore its functionality will be extended as soon as at will be needed

2. This util was tested only on arch-linux and fedora with CentOS-7 as a VM, other distributions of VMs / OSs will be added later

## Quickstart

Before we start, let's do some preparations.

1. Initialize VKDBG with command. After that, you can use it from anywhere.
```bash
./vkdbg bootstrap
```

2. Find a QCOW2 image of the machine you want or create it by yourself and then find some debug sources in rpm format (deb is coming soon). Your best choice is fedora / CentOS images as both of them have good debug sources and kernel images.


3. Let's create your first VKDBG bundle, a command below creates a virtual machine environment bundle for fast migration.

```bash
./vkgdb bundle create -p <path_to_qcow> -r <path_to_dir_with_rpms> [-n bundle_name] 
```

4. This process will take some time and it will take even longer, depending on the size of your image and sources, we can continue after bundle creation. 
A command to create a VKDBG environment for your VM

```bash
 ./vkdbg vm init <machine_name> -p <path_to_bundle> 
```

5. If you don't have a virtual machine, create it following the instructions from the output of the previous command

6. Well, all's done! Now, you can debug and manipulate this machine in any way you want as a simple program. Just run

```bash
./vkdbg vm set-current <machine_name> (optionally)
./vkdbg vm start
./vkdbg vm debug
```

For more information, you can use ```--help``` for almost any command.

## Read more
* https://access.redhat.com/blogs/766093/posts/2690881
* https://fedoraproject.org/wiki/How_to_debug_Virtualization_problems
