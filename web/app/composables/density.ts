import { useLocalStorage } from '@vueuse/core'

// UI density, remembered per browser (like the theme). The CSS in assets/css/main.css scales the root font size
// and Tailwind's --spacing for comfortable and compact, so every component follows without per-component edits.
export type Density = 'default' | 'comfortable' | 'compact'

export const DENSITIES: { value: Density; label: string; hint: string; description: string }[] = [
  { value: 'default', label: 'Default', hint: 'Wide', description: 'Roomy spacing and full-size text.' },
  { value: 'comfortable', label: 'Comfortable', hint: 'Medium', description: 'A little tighter; more fits on screen.' },
  { value: 'compact', label: 'Compact', hint: 'Small', description: 'Dense tables and cards for big fleets.' },
]

export function isDensity(v: unknown): v is Density {
  return v === 'default' || v === 'comfortable' || v === 'compact'
}

export function applyDensity(v: unknown) {
  if (typeof document === 'undefined') return
  document.documentElement.dataset.density = isDensity(v) ? v : 'default'
}

export function useDensity() {
  // useLocalStorage falls back to the default when storage is blocked (private mode, disabled site data)
  return useLocalStorage<Density>('krgn.density', 'default', { listenToStorageChanges: true })
}
