import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import OverviewView from './views/OverviewView.vue'
import ActorsView from './views/ActorsView.vue'
import IncidentsView from './views/IncidentsView.vue'
import ResearchView from './views/ResearchView.vue'
import AttackMapView from './views/AttackMapView.vue'
import SourceView from './views/SourceView.vue'
import EventsView from './views/EventsView.vue'
import SpokesView from './views/SpokesView.vue'
import SettingsView from './views/SettingsView.vue'
import ReplayView from './views/ReplayView.vue'
import './style.css'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: OverviewView },
    { path: '/actors', component: ActorsView },
    { path: '/incidents', component: IncidentsView },
    { path: '/research', component: ResearchView },
    { path: '/map', component: AttackMapView },
    { path: '/sources/:source', component: SourceView, props: true },
    { path: '/events', component: EventsView },
    { path: '/spokes', component: SpokesView },
    { path: '/settings', component: SettingsView },
    { path: '/replays/:view', component: ReplayView, props: true },
  ],
})

createApp(App).use(router).mount('#app')
