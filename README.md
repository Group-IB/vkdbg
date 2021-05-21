# VKDBG

## General-purpose

This util intended for supporting in kernel / kernel module development or debugging. The main purpose is to automate routines like VMs management, migration, processing, and so on.

## Before you start

1. This util currently in development and being in use for work purposes, therefore functionality will be extended as
   soon as at will be in need

2. This util was tested only on arch-linux and fedora with CentOS-7 as VM, other distributions of VM / OS will be added later

## Quickstart

Before we start, let's do some preparations.

1. Find some QCOW2 image of the machine you want or create it by yourself and then, find some debug sources in rpm format (deb is coming soon). Your better choice is fedora / CentOS images, both of them have good debug sources and kernel images.


2. Then, when you've done the first step, let's create your first VKDBG bundle.

```./vkgdb bundle create -p <path_to_qcow> -r <path_to_dir_with_rpms> [-n bundle_name] ```

3. This process is long and becomes longer as the bigger size of images and sources, but when a bundle will be created, we can continue! Create VKDBG environment for VM

``` ./vkdbg vm init <machine_name> -p <path_to_bundle> ```

4. Further if you don't have a virtual machine, create it following instructions from the output of the previous command

5. Well, all's done! Now, you can manipulate and debug this machine as a simple program. Just run

```
./vkdbg vm set-current <machine_name> (optionally)
./vkdbg vm start
./vkdbg vm debug
```

For more information, you can use ```--help``` flag almost for every command