<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

type WorkerStatus = 'pending' | 'running' | 'done' | 'failed'

interface Worker {
  id: string
  role: string
  roleColor: string
  task: string
  status: WorkerStatus
  progress: number
  finding?: string
}

type EvidenceKind = 'observed' | 'correlated' | 'inferred' | 'verified' | 'conflicted'

interface Evidence {
  id: string
  role: string
  kind: EvidenceKind
  title: string
  summary: string
  entities: string[]
  time: number
}

interface Hypothesis {
  id: string
  title: string
  status: 'OPEN' | 'SUPPORTED' | 'WEAKENED' | 'REJECTED'
  confidence: number
  previousConfidence?: number
  rationale: string
}

interface TimelineEntry {
  id: string
  type: 'ai' | 'human' | 'system' | 'warn'
  text: string
  time: number
}

interface PendingQuestion {
  question: string
  reason: string
  options: Array<{ label: string; value: string }>
}

const started = ref(false)
const paused = ref(false)
const speed = ref(1)

const objective = 'Credential theft on WORKSTATION-JDOES. PowerShell observed spawning unusual children.'
const hypothesis =
  'Stolen credentials are being used to authenticate to internal services from WORKSTATION-JDOES.'

const workers = ref<Worker[]>([
  { id: 'w-endpoint', role: 'Endpoint', roleColor: '#60A5FA', task: 'Trace PowerShell process tree', status: 'pending', progress: 0 },
  { id: 'w-network', role: 'Network', roleColor: '#38BDF8', task: 'Analyze outbound connections', status: 'pending', progress: 0 },
  { id: 'w-identity', role: 'Identity', roleColor: '#A78BFA', task: 'Audit authentication events', status: 'pending', progress: 0 },
  { id: 'w-intel', role: 'Threat Intel', roleColor: '#F5B942', task: 'Check destination reputation', status: 'pending', progress: 0 },
  { id: 'w-historical', role: 'Historical', roleColor: '#7F8994', task: 'Compare against host baseline', status: 'pending', progress: 0 },
  { id: 'w-challenger', role: 'Challenger', roleColor: '#F05252', task: 'Stress-test the hypothesis', status: 'pending', progress: 0 },
])

const evidence = ref<Evidence[]>([])
const hypotheses = ref<Hypothesis[]>([
  {
    id: 'h-cred',
    title: 'Credential theft in progress',
    status: 'OPEN',
    confidence: 0.45,
    rationale: 'Suspected from PowerShell execution on WORKSTATION-JDOES.',
  },
])
const timeline = ref<TimelineEntry[]>([])
const pendingQuestion = ref<PendingQuestion | null>(null)
const humanAnswer = ref<string | null>(null)
const challengerFinding = ref<string | null>(null)
const synthesis = ref<string | null>(null)

let timers: ReturnType<typeof setTimeout>[] = []
function schedule(fn: () => void, ms: number) {
  const id = setTimeout(() => {
    if (!paused.value) fn()
  }, ms / speed.value)
  timers.push(id)
  return id
}

function pushTimeline(type: TimelineEntry['type'], text: string) {
  timeline.value.unshift({ id: `t-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, type, text, time: Date.now() })
  if (timeline.value.length > 20) timeline.value.length = 20
}

function addEvidence(ev: Omit<Evidence, 'id' | 'time'>) {
  evidence.value.unshift({ ...ev, id: `e-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, time: Date.now() })
  if (evidence.value.length > 12) evidence.value.length = 12
}

function setWorker(id: string, patch: Partial<Worker>) {
  const idx = workers.value.findIndex((w) => w.id === id)
  if (idx >= 0) workers.value[idx] = { ...workers.value[idx], ...patch }
}

function adjustHypothesis(id: string, delta: number, status?: Hypothesis['status'], rationale?: string) {
  const h = hypotheses.value.find((x) => x.id === id)
  if (!h) return
  h.previousConfidence = h.confidence
  h.confidence = Math.max(0, Math.min(1, h.confidence + delta))
  if (status) h.status = status
  if (rationale) h.rationale = rationale
}

function runScript() {
  if (started.value) return
  started.value = true
  pushTimeline('system', 'Investigation created. Planner generated 6-worker plan.')

  schedule(() => {
    pushTimeline('ai', '5 domain investigators launched in parallel.')
    pushTimeline('ai', 'Challenger agent queued behind them.')
    for (const w of workers.value) {
      setWorker(w.id, { status: 'running', progress: 5 })
    }
  }, 600)

  schedule(() => setWorker('w-endpoint', { progress: 35 }), 1400)
  schedule(() => {
    setWorker('w-endpoint', { progress: 100, status: 'done', finding: 'powershell.exe → cmd.exe → rundll32.exe chain (unusual)' })
    addEvidence({
      role: 'Endpoint',
      kind: 'observed',
      title: 'Unusual parent-child process chain',
      summary: 'powershell.exe (PID 4421) spawned cmd.exe, which launched rundll32.exe to load a non-standard DLL.',
      entities: ['WORKSTATION-JDOES', 'powershell.exe', 'rundll32.exe'],
    })
    pushTimeline('ai', 'Endpoint: PowerShell spawned rundll32.exe via cmd.exe — atypical for this host.')
  }, 2400)

  schedule(() => setWorker('w-network', { progress: 40 }), 2200)
  schedule(() => {
    setWorker('w-network', { progress: 100, status: 'done', finding: 'Outbound TLS to update-cdn-east[.]xyz:443' })
    addEvidence({
      role: 'Network',
      kind: 'observed',
      title: 'Outbound connection to non-corporate domain',
      summary: 'WORKSTATION-JDOES initiated TLS to update-cdn-east[.]xyz, never seen on this network segment.',
      entities: ['update-cdn-east[.]xyz', 'WORKSTATION-JDOES'],
    })
    pushTimeline('ai', 'Network: TLS beacon to update-cdn-east[.]xyz — new destination.')
  }, 3200)

  schedule(() => setWorker('w-identity', { progress: 30 }), 3000)
  schedule(() => {
    setWorker('w-identity', { progress: 100, status: 'done', finding: 'Logon Type 10 (RDP) from WORKSTATION-JDOES to DC01 for j.doe' })
    addEvidence({
      role: 'Identity',
      kind: 'observed',
      title: 'Unusual interactive logon to DC01',
      summary: 'Account j.doe authenticated Logon Type 10 (RDP) from WORKSTATION-JDOES to DC01 at 03:14 UTC.',
      entities: ['j.doe', 'DC01', 'WORKSTATION-JDOES'],
    })
    pushTimeline('ai', 'Identity: j.doe RDP-logged into DC01 from the suspect workstation.')
    adjustHypothesis('h-cred', 0.2, 'SUPPORTED', 'Process, network, and identity observations align with credential theft.')
  }, 4200)

  schedule(() => setWorker('w-intel', { progress: 45 }), 3800)
  schedule(() => {
    setWorker('w-intel', { progress: 100, status: 'done', finding: 'Domain registered 11 days ago, low reputation' })
    addEvidence({
      role: 'Threat Intel',
      kind: 'correlated',
      title: 'Suspicious domain reputation',
      summary: 'update-cdn-east[.]xyz registered 11 days ago. Low reputation across 3 feeds. Resolves to a VPS range commonly used for staging.',
      entities: ['update-cdn-east[.]xyz'],
    })
    pushTimeline('ai', 'Threat Intel: domain is low-reputation, very recently registered.')
  }, 5200)

  schedule(() => setWorker('w-historical', { progress: 50 }), 4400)
  schedule(() => {
    setWorker('w-historical', { progress: 100, status: 'done', finding: 'No PowerShell history on this host in 90 days' })
    addEvidence({
      role: 'Historical',
      kind: 'verified',
      title: 'No baseline precedent',
      summary: 'No prior PowerShell activity from WORKSTATION-JDOES in the last 90 days. This is a first-seen behavior.',
      entities: ['WORKSTATION-JDOES'],
    })
    pushTimeline('ai', 'Historical: first-seen behavior for this host.')
  }, 5800)

  schedule(() => setWorker('w-challenger', { progress: 25 }), 5600)
  schedule(() => {
    challengerFinding.value =
      'PowerShell itself is common in this environment — it is not sufficient evidence. The credential-theft hypothesis depends on the rundll32 spawn AND the new outbound destination. Both must hold.'
    pushTimeline('warn', 'Challenger: PowerShell usage alone is not evidence. Hypothesis needs both unusual process chain AND new destination.')
  }, 6800)
  schedule(() => {
    setWorker('w-challenger', { progress: 100, status: 'done', finding: 'Hypothesis requires both unusual chain and new destination' })
  }, 7600)

  schedule(() => {
    synthesis.value =
      'Credential theft hypothesis STRENGTHENED. Process tree anomaly, novel outbound destination, and an unusual RDP-to-DC01 logon are correlated to account j.doe. Threat-intel correlation supports the destination. Historical baseline confirms first-seen behavior.'
    pushTimeline('ai', 'AI synthesis: credential theft hypothesis strengthened.')
    pendingQuestion.value = {
      question: 'Is account j.doe normally used from WORKSTATION-JDOES?',
      reason: 'Highest-impact unknown. If yes → likely compromised account. If no → also likely, but response path differs.',
      options: [
        { label: 'Yes — primary workstation', value: 'yes-primary' },
        { label: 'Occasionally', value: 'occasionally' },
        { label: 'No — first time seen', value: 'no' },
      ],
    }
    pushTimeline('system', 'Recommending next-best question to human.')
  }, 8800)
}

function answerQuestion(value: string) {
  if (!pendingQuestion.value) return
  humanAnswer.value = value
  const choice = pendingQuestion.value.options.find((o) => o.value === value)
  pushTimeline('human', `Human answered: ${choice?.label ?? value}`)
  pendingQuestion.value = null

  if (value === 'no') {
    schedule(() => {
      adjustHypothesis('h-cred', 0.15, 'SUPPORTED', 'First-time workstation logon for j.doe significantly raises compromise likelihood.')
      pushTimeline('ai', 'Identity investigator spawned: pull last 7 days of j.doe logon activity.')
      setWorker('w-endpoint', { status: 'running', progress: 0, task: 'Pivot: collect j.doe auth history (human-directed)' })
    }, 400)
    schedule(() => {
      setWorker('w-endpoint', { progress: 60, status: 'running' })
      addEvidence({
        role: 'Identity',
        kind: 'inferred',
        title: 'j.doe first-time login from this workstation',
        summary: 'Human confirmed j.doe has never authenticated from WORKSTATION-JDOES. Credential theft is the most plausible explanation.',
        entities: ['j.doe', 'WORKSTATION-JDOES'],
      })
    }, 1400)
    schedule(() => {
      setWorker('w-endpoint', { progress: 100, status: 'done', finding: 'Confirmed: no prior j.doe logons from this host' })
      synthesis.value =
        'Conclusion: high-confidence credential theft. j.doe account should be considered compromised. Recommended actions: disable account, force password reset, hunt for the same destination across the fleet.'
      pushTimeline('ai', 'AI synthesis updated: high-confidence credential theft.')
    }, 2400)
  } else if (value === 'occasionally') {
    schedule(() => {
      adjustHypothesis('h-cred', 0.05, 'SUPPORTED', 'Occasional usage raises but does not confirm compromise.')
      synthesis.value =
        'Hypothesis still supported but lower priority. Recommend: enrich with j.doe sign-in logs for last 30 days to spot anomalies.'
      pushTimeline('ai', 'AI synthesis: hypothesis supported, lower priority.')
    }, 600)
  } else {
    schedule(() => {
      adjustHypothesis('h-cred', -0.05, 'OPEN', 'Primary-workstation login reduces but does not eliminate compromise risk.')
      synthesis.value =
        'Hypothesis weakened slightly. Still recommend monitoring DC01 access from this host and reviewing destination reputation hits.'
      pushTimeline('ai', 'AI synthesis: hypothesis weakened slightly.')
    }, 600)
  }
}

function reset() {
  timers.forEach(clearTimeout)
  timers = []
  started.value = false
  paused.value = false
  workers.value = workers.value.map((w) => ({ ...w, status: 'pending', progress: 0, finding: undefined }))
  evidence.value = []
  hypotheses.value = [{
    id: 'h-cred',
    title: 'Credential theft in progress',
    status: 'OPEN',
    confidence: 0.45,
    rationale: 'Suspected from PowerShell execution on WORKSTATION-JDOES.',
  }]
  timeline.value = []
  pendingQuestion.value = null
  humanAnswer.value = null
  challengerFinding.value = null
  synthesis.value = null
}

function togglePause() {
  paused.value = !paused.value
}

function changeSpeed(s: number) {
  speed.value = s
}

function confidencePct(h: Hypothesis): number {
  return Math.round(h.confidence * 100)
}

function deltaPct(h: Hypothesis): number | null {
  if (h.previousConfidence == null) return null
  return Math.round((h.confidence - h.previousConfidence) * 100)
}

function formatTime(ts: number): string {
  const d = new Date(ts)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

onMounted(() => {
  // Auto-start after a short delay so users see the launch
  setTimeout(runScript, 800)
})

onBeforeUnmount(() => {
  timers.forEach(clearTimeout)
})
</script>

<template>
  <div class="live-demo-shell">
    <div class="demo-frame">
      <div class="ctrl-bar">
        <span class="role-chip" style="border-color: var(--soc-accent-primary); color: var(--soc-accent-primary)">
          <span class="pulse-dot"></span>
          LIVE
        </span>
        <span style="color: var(--soc-text-muted)">|</span>
        <span><strong style="color: var(--soc-text-primary)">INV-2841</strong> · Credential Theft on WORKSTATION-JDOES</span>
        <span style="flex: 1"></span>
        <button class="ctrl-btn" @click="togglePause">{{ paused ? 'Resume' : 'Pause' }}</button>
        <button class="ctrl-btn" @click="changeSpeed(0.5)" :style="speed === 0.5 ? 'border-color: var(--soc-accent-primary); color: var(--soc-text-primary)' : ''">0.5×</button>
        <button class="ctrl-btn" @click="changeSpeed(1)" :style="speed === 1 ? 'border-color: var(--soc-accent-primary); color: var(--soc-text-primary)' : ''">1×</button>
        <button class="ctrl-btn" @click="changeSpeed(2)" :style="speed === 2 ? 'border-color: var(--soc-accent-primary); color: var(--soc-text-primary)' : ''">2×</button>
        <button class="ctrl-btn" @click="reset">Restart demo</button>
      </div>

      <div style="display: grid; grid-template-columns: 320px 1fr 360px; gap: 12px; padding: 12px; background: var(--soc-bg-canvas)">
        <!-- LEFT COLUMN: Human Objective + Hypothesis + Context -->
        <div style="display: flex; flex-direction: column; gap: 12px; min-width: 0">
          <div class="panel">
            <div class="panel-header">
              <span style="color: var(--soc-accent-primary)">●</span> HUMAN OBJECTIVE
            </div>
            <div class="panel-body" style="color: var(--soc-text-primary)">
              {{ objective }}
            </div>
          </div>

          <div class="panel">
            <div class="panel-header">
              <span style="color: var(--soc-accent-primary)">●</span> HUMAN CONTEXT
            </div>
            <div class="panel-body" style="display: flex; flex-direction: column; gap: 8px">
              <div>
                <div style="font-size: 10.5px; color: var(--soc-text-muted); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 4px">Hypothesis</div>
                <div style="color: var(--soc-text-primary)">{{ hypothesis }}</div>
              </div>
              <div>
                <div style="font-size: 10.5px; color: var(--soc-text-muted); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 4px">Constraints</div>
                <div>• PowerShell is common in this environment</div>
                <div>• Focus on unusual execution chains & lateral movement</div>
              </div>
              <div>
                <div style="font-size: 10.5px; color: var(--soc-text-muted); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 4px">Risk tolerance</div>
                <div><span class="role-chip" style="color: var(--soc-warning-main); border-color: var(--soc-warning-main)">MEDIUM</span> <span style="margin-left: 6px">Active investigation, evidence-first</span></div>
              </div>
            </div>
          </div>

          <div class="panel" style="flex: 1; min-height: 0; display: flex; flex-direction: column">
            <div class="panel-header">
              <span style="color: var(--soc-ai-primary)">●</span> TIMELINE
            </div>
            <div class="panel-body" style="flex: 1; overflow-y: auto; max-height: 280px">
              <div v-if="timeline.length === 0" style="color: var(--soc-text-muted); text-align: center; padding: 12px 0">
                Awaiting first event…
              </div>
              <div v-for="t in timeline" :key="t.id" class="fade-in" style="display: flex; gap: 8px; align-items: flex-start; padding: 5px 0; border-bottom: 1px solid var(--soc-border-subtle)">
                <div class="timeline-dot" :class="t.type" :style="t.type === 'warn' ? 'background: var(--soc-warning-main)' : t.type === 'human' ? 'background: var(--soc-accent-primary)' : t.type === 'system' ? 'background: var(--soc-text-muted)' : ''"></div>
                <div style="flex: 1; font-size: 11.5px">
                  <div style="color: var(--soc-text-secondary)">{{ t.text }}</div>
                  <div style="font-size: 10px; color: var(--soc-text-muted); font-family: 'JetBrains Mono', monospace">{{ formatTime(t.time) }}</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- CENTER COLUMN: Plan + Workers + Evidence -->
        <div style="display: flex; flex-direction: column; gap: 12px; min-width: 0">
          <div class="panel">
            <div class="panel-header">
              <span style="color: var(--soc-ai-primary)">●</span> AI-GENERATED INVESTIGATION PLAN
            </div>
            <div class="panel-body" style="display: flex; flex-direction: column; gap: 8px">
              <div style="font-size: 12px; color: var(--soc-text-secondary); margin-bottom: 2px">
                <strong style="color: var(--soc-text-primary)">Goal:</strong> confirm or refute credential theft within 5 minutes of evidence.
              </div>
              <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px">
                <div style="background: var(--soc-bg-secondary); border: 1px solid var(--soc-border-subtle); border-radius: 8px; padding: 8px 10px">
                  <div style="font-size: 10.5px; color: var(--soc-text-muted); text-transform: uppercase; letter-spacing: 0.06em">Endpoint</div>
                  <div style="font-size: 12px; color: var(--soc-text-primary); margin-top: 2px">Trace process tree</div>
                </div>
                <div style="background: var(--soc-bg-secondary); border: 1px solid var(--soc-border-subtle); border-radius: 8px; padding: 8px 10px">
                  <div style="font-size: 10.5px; color: var(--soc-text-muted); text-transform: uppercase; letter-spacing: 0.06em">Network + Identity</div>
                  <div style="font-size: 12px; color: var(--soc-text-primary); margin-top: 2px">Correlate connections ↔ logons</div>
                </div>
                <div style="background: var(--soc-bg-secondary); border: 1px solid var(--soc-border-subtle); border-radius: 8px; padding: 8px 10px">
                  <div style="font-size: 10.5px; color: var(--soc-text-muted); text-transform: uppercase; letter-spacing: 0.06em">Intel + Historical</div>
                  <div style="font-size: 12px; color: var(--soc-text-primary); margin-top: 2px">Reputation + baseline check</div>
                </div>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-header">
              <span style="color: var(--soc-ai-primary)">●</span> PARALLEL WORKERS
              <span style="margin-left: auto; color: var(--soc-text-muted); font-weight: 400; text-transform: none; letter-spacing: normal">
                {{ workers.filter(w => w.status === 'running').length }} running · {{ workers.filter(w => w.status === 'done').length }} done
              </span>
            </div>
            <div class="panel-body" style="display: flex; flex-direction: column; gap: 8px">
              <div v-for="w in workers" :key="w.id" class="worker-row" :class="{ 'fade-in': w.status === 'running' }">
                <span class="role-chip" :style="`color: ${w.roleColor}; border-color: ${w.roleColor}`">{{ w.role }}</span>
                <div style="flex: 1; min-width: 0">
                  <div style="display: flex; align-items: center; gap: 8px">
                    <span style="color: var(--soc-text-primary); font-weight: 500">{{ w.task }}</span>
                  </div>
                  <div style="display: flex; align-items: center; gap: 8px; margin-top: 4px">
                    <div class="progress-track">
                      <div class="progress-fill" :class="{ done: w.status === 'done', failed: w.status === 'failed' }" :style="`width: ${w.progress}%`"></div>
                    </div>
                    <span :class="`status-${w.status === 'running' ? 'running' : w.status}`" style="font-size: 11px; font-family: 'JetBrains Mono', monospace; min-width: 60px; text-align: right">
                      <span v-if="w.status === 'pending'">queued</span>
                      <span v-else-if="w.status === 'running'">{{ w.progress }}%</span>
                      <span v-else-if="w.status === 'done'">done</span>
                      <span v-else>failed</span>
                    </span>
                  </div>
                  <div v-if="w.finding" class="fade-in" style="margin-top: 4px; font-size: 11.5px; color: var(--soc-success-main)">
                    ✓ {{ w.finding }}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="panel" style="flex: 1; min-height: 0; display: flex; flex-direction: column">
            <div class="panel-header">
              <span style="color: var(--soc-info-main)">●</span> EVIDENCE FEED
              <span style="margin-left: auto; color: var(--soc-text-muted); font-weight: 400; text-transform: none; letter-spacing: normal">
                {{ evidence.length }} items · auto-correlated
              </span>
            </div>
            <div class="panel-body" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; max-height: 360px">
              <div v-if="evidence.length === 0" style="color: var(--soc-text-muted); text-align: center; padding: 16px 0">
                Evidence will appear as workers complete…
              </div>
              <div v-for="e in evidence" :key="e.id" class="evidence-card feed-enter" :class="e.kind">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px">
                  <span class="role-chip" style="font-size: 10px; padding: 2px 6px">{{ e.role }}</span>
                  <span style="font-size: 10px; color: var(--soc-text-muted); text-transform: uppercase; letter-spacing: 0.06em">{{ e.kind }}</span>
                </div>
                <div style="font-weight: 600; color: var(--soc-text-primary); margin-bottom: 4px">{{ e.title }}</div>
                <div style="color: var(--soc-text-secondary); font-size: 12px">{{ e.summary }}</div>
                <div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px">
                  <span v-for="ent in e.entities" :key="ent" class="entity-pill">{{ ent }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- RIGHT COLUMN: Hypotheses + Synthesis + Next Question -->
        <div style="display: flex; flex-direction: column; gap: 12px; min-width: 0">
          <div class="panel">
            <div class="panel-header">
              <span style="color: var(--soc-warning-main)">●</span> HYPOTHESES
            </div>
            <div class="panel-body" style="display: flex; flex-direction: column; gap: 10px">
              <div v-for="h in hypotheses" :key="h.id" class="hypothesis-card">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px">
                  <span style="font-weight: 600; color: var(--soc-text-primary); flex: 1; font-size: 13px">{{ h.title }}</span>
                  <span class="role-chip" :style="h.status === 'SUPPORTED' ? 'color: var(--soc-success-main); border-color: var(--soc-success-main)' : h.status === 'WEAKENED' ? 'color: var(--soc-warning-main); border-color: var(--soc-warning-main)' : 'color: var(--soc-text-muted)'">{{ h.status }}</span>
                </div>
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px">
                  <div class="conf-bar" style="flex: 1">
                    <div class="conf-fill" :class="deltaPct(h) != null ? (deltaPct(h)! > 0 ? 'up' : 'down') : ''" :style="`width: ${confidencePct(h)}%`"></div>
                  </div>
                  <span style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--soc-text-primary); min-width: 36px; text-align: right">{{ confidencePct(h) }}%</span>
                  <span v-if="deltaPct(h) != null" :style="`font-family: 'JetBrains Mono', monospace; font-size: 11px; color: ${deltaPct(h)! > 0 ? 'var(--soc-success-main)' : 'var(--soc-danger-main)'}`">
                    {{ deltaPct(h)! > 0 ? '+' : '' }}{{ deltaPct(h) }}%
                  </span>
                </div>
                <div style="font-size: 11.5px; color: var(--soc-text-muted)">{{ h.rationale }}</div>
              </div>
            </div>
          </div>

          <div v-if="challengerFinding" class="challenger-banner feed-enter">
            <span style="color: var(--soc-warning-main); font-weight: 700">⚠</span>
            <div>
              <div style="font-size: 10.5px; color: var(--soc-warning-main); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px">CHALLENGER · CONTRADICTION</div>
              <div style="color: var(--soc-text-primary)">{{ challengerFinding }}</div>
            </div>
          </div>

          <div v-if="synthesis" class="ai-banner feed-enter">
            <span style="color: var(--soc-ai-primary); font-weight: 700">◆</span>
            <div>
              <div style="font-size: 10.5px; color: var(--soc-ai-primary); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px">AI SYNTHESIS</div>
              <div>{{ synthesis }}</div>
            </div>
          </div>

          <div v-if="pendingQuestion" class="qa-prompt feed-enter">
            <div style="font-size: 10.5px; color: var(--soc-accent-primary); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px">NEXT-BEST QUESTION</div>
            <div style="font-weight: 600; color: var(--soc-text-primary); margin-bottom: 4px">{{ pendingQuestion.question }}</div>
            <div style="font-size: 11.5px; color: var(--soc-text-muted); margin-bottom: 10px">{{ pendingQuestion.reason }}</div>
            <div class="qa-buttons">
              <button v-for="o in pendingQuestion.options" :key="o.value" class="qa-btn" :class="o.value === 'no' ? 'primary' : ''" @click="answerQuestion(o.value)">
                {{ o.label }}
              </button>
            </div>
          </div>

          <div v-else-if="humanAnswer" class="human-banner fade-in">
            <span style="color: var(--soc-accent-primary); font-weight: 700">→</span>
            <div>
              <div style="font-size: 10.5px; color: var(--soc-accent-primary); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px">HUMAN ANSWERED · INVESTIGATION CONTINUES</div>
              <div style="font-size: 12px; color: var(--soc-text-muted)">Watch new evidence arrive and the hypothesis update in real time.</div>
            </div>
          </div>

          <div v-else class="panel" style="flex: 1">
            <div class="panel-header">
              <span style="color: var(--soc-text-muted)">●</span> AWAITING NEXT-BEST WORK
            </div>
            <div class="panel-body" style="color: var(--soc-text-muted); text-align: center; padding: 16px 0">
              The AI team will surface the highest-value next step once the current sweep completes.
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
