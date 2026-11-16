<script setup lang="ts">
// disc: round backing for small sizes (sidebar, mobile header), like public/favicon.svg
defineProps<{ disc?: boolean }>()
</script>

<template>
  <!-- traced from assets/logo/minimal-*.png; same paths as public/favicon.svg -->
  <svg :viewBox="disc ? '200 147 890 890' : '320 267 650 650'" aria-hidden="true">
    <circle v-if="disc" class="fill-muted stroke-border" cx="645" cy="592" r="430" stroke-width="28" />
    <polygon class="fill-[#adacac] dark:fill-[#d6d3d0]" points="382,439 660,272 901,420 817,469 660,375 382,540" />
    <g class="fill-[#5e5e5f] dark:fill-[#727172]">
      <polygon points="485,506 485,670 557,725 557,843 390,700 390,563" />
      <polygon points="907,533 907,697 753,842 753,733 815,683 815,589" />
    </g>
    <g class="fill-[#2c2c2c] dark:fill-[#e8e4de]">
      <polygon
        points="660,447 772,516 772,584 660,515 577,565 577,640 632,682 632,910 575,855 575,697 522,655 522,532"
      />
      <polygon points="784,636 784,678 734,714 734,856 684,908 684,697" />
      <polygon points="619,574 655,597 655,613 619,636 619,622 640,605 619,588" />
      <rect x="669" y="624" width="54" height="14" />
    </g>
    <polygon fill="#f65f0a" points="774,518 908,438 908,501 774,583" />
  </svg>
</template>
