<template>
  <!-- public/logo-*.png are the delivered icons, unchanged (DESIGN.md): the Circular Kurogane Terminal Emblem in light
       mode, kurogane-dark-minimal in dark mode -->
  <span class="inline-block shrink-0" aria-hidden="true">
    <img
      src="/logo-light-128.png"
      srcset="/logo-light-128.png 1x, /logo-light-256.png 2x"
      alt=""
      width="128"
      height="128"
      class="size-full rounded-full dark:hidden"
    />
    <img
      src="/logo-128.png"
      srcset="/logo-128.png 1x, /logo-256.png 2x"
      alt=""
      width="128"
      height="128"
      class="hidden size-full rounded-full dark:block"
    />
  </span>
</template>
