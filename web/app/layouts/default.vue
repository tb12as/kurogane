<script setup lang="ts">
import { useDark, useToggle } from '@vueuse/core'
import {
  Activity,
  Bell,
  FileClock,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  Settings,
  ShieldCheck,
  Sun,
  X,
} from '@lucide/vue'

const me = useMe()
const fleet = useFleet()
const live = useLive()
const dark = useDark()
const toggleDark = useToggle(dark)
const navOpen = ref(false)
const route = useRoute()
watch(
  () => route.fullPath,
  () => (navOpen.value = false),
)

const nav = computed(() => [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  ...(fleet.value ? [] : [{ to: '/servers/local', label: 'Metrics', icon: Activity }]),
  { to: '/ssh', label: 'SSH', icon: KeyRound },
  { to: '/hardening', label: 'Hardening', icon: ShieldCheck },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  ...(fleet.value ? [{ to: '/fleet', label: 'Fleet', icon: Network }] : []),
  { to: '/audit', label: 'Audit log', icon: FileClock },
  { to: '/settings', label: 'Settings', icon: Settings },
])

function active(to: string) {
  return to === '/' ? route.path === '/' : route.path.startsWith(to)
}

onMounted(startStream)
</script>

<template>
  <div class="min-h-dvh md:grid md:grid-cols-[14rem_1fr]">
    <a
      href="#main"
      class="sr-only z-50 rounded bg-background p-2 focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
    >
      Skip to content
    </a>

    <header class="flex items-center justify-between border-b px-4 py-3 md:hidden">
      <span class="font-semibold">ServerKeeper</span>
      <Button
        variant="ghost"
        size="icon"
        :aria-expanded="navOpen"
        aria-controls="sidenav"
        aria-label="Menu"
        @click="navOpen = !navOpen"
      >
        <X v-if="navOpen" />
        <Menu v-else />
      </Button>
    </header>

    <aside
      id="sidenav"
      :class="[navOpen ? 'block' : 'hidden', 'border-b md:sticky md:top-0 md:block md:h-dvh md:border-r md:border-b-0']"
    >
      <div class="flex h-full flex-col gap-4 p-3">
        <NuxtLink to="/" class="hidden px-2 pt-1 text-lg font-semibold md:block">ServerKeeper</NuxtLink>
        <nav aria-label="Main" class="flex flex-col gap-0.5">
          <NuxtLink
            v-for="n in nav"
            :key="n.to"
            :to="n.to"
            :class="[
              'flex items-center gap-2 rounded-md px-2 py-2 text-sm hover:bg-accent',
              active(n.to) ? 'bg-accent font-medium' : 'text-muted-foreground',
            ]"
            :aria-current="active(n.to) ? 'page' : undefined"
          >
            <component :is="n.icon" class="size-4" aria-hidden="true" />
            {{ n.label }}
          </NuxtLink>
        </nav>
        <div class="mt-auto space-y-2 border-t pt-3 text-sm">
          <p class="flex items-center gap-2 px-2 text-xs text-muted-foreground">
            <span
              :class="['size-2 rounded-full', live.connected.value ? 'bg-ok' : 'bg-muted-foreground']"
              aria-hidden="true"
            />
            {{ live.connected.value ? 'Live' : 'Reconnecting…' }}
          </p>
          <p class="truncate px-2" :title="me?.actor">
            {{ me?.actor }}
            <span class="text-muted-foreground">· {{ me?.role }}</span>
          </p>
          <div class="flex gap-1">
            <Button
              variant="ghost"
              size="sm"
              :aria-label="dark ? 'Use light theme' : 'Use dark theme'"
              @click="toggleDark()"
            >
              <Sun v-if="dark" />
              <Moon v-else />
            </Button>
            <Button variant="ghost" size="sm" @click="logout">
              <LogOut />
              Sign out
            </Button>
          </div>
        </div>
      </div>
    </aside>

    <div class="min-w-0">
      <PendingBanner />
      <main id="main" tabindex="-1" class="mx-auto max-w-7xl space-y-6 p-4 md:p-6">
        <slot />
      </main>
    </div>
  </div>
</template>
