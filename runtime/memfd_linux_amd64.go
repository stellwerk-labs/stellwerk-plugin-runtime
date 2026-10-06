package main

// memfd_create is syscall 319 on linux/amd64; the frozen syscall package
// predates it.
const sysMemfdCreate = 319
