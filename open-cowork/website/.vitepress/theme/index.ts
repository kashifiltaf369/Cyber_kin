import DefaultTheme from 'vitepress/theme'
import LiveInvestigationDemo from './LiveInvestigationDemo.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhance({ app }: { app: any }) {
    app.component('LiveInvestigationDemo', LiveInvestigationDemo)
  },
}
