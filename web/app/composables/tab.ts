// tab state mirrored in ?tab= so tabs are linkable and survive reload
export function useTab(def: string) {
  const route = useRoute()
  return computed({
    get: () => (typeof route.query.tab === 'string' ? route.query.tab : def),
    set: (tab: string) => {
      navigateTo({ query: { ...route.query, tab } }, { replace: true })
    },
  })
}
