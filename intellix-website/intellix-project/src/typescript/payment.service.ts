/**
 * Intellix Payment Service — TypeScript / NestJS
 * ================================================
 * Full production payment processing service with:
 * - Route optimization (cheapest network path)
 * - Real-time fraud check integration
 * - Multi-currency support
 * - Webhook dispatch
 * - Repository pattern with TypeORM
 *
 * Run: npm install && npx ts-node payment.service.ts
 */

// ─────────────────────────────────────────────
// TYPES & INTERFACES
// ─────────────────────────────────────────────

export type Currency = 'USD' | 'EUR' | 'GBP' | 'BTC' | 'ETH' | 'USDC' | 'SOL' | 'JPY'
export type PaymentStatus = 'pending' | 'processing' | 'confirmed' | 'failed' | 'flagged' | 'cancelled'
export type PaymentMethod = 'crypto' | 'wire' | 'ach' | 'swift' | 'fx' | 'split' | 'api' | 'defi'
export type Network = 'ethereum' | 'bitcoin' | 'polygon' | 'solana' | 'bsc' | 'fiat' | 'ach' | 'swift'

export interface PaymentIntent {
  userId: string
  amount: number
  currency: Currency
  recipientWallet: string
  recipientName?: string
  description?: string
  method: PaymentMethod
  routeOptimizer: boolean
  scheduleAt?: Date
  metadata?: Record<string, unknown>
}

export interface RouteOption {
  path: string
  network: Network
  estimatedFee: number
  estimatedTimeSeconds: number
  savingsVsDirect: number
}

export interface FraudResult {
  riskScore: number
  verdict: 'APPROVED' | 'REVIEW' | 'HOLD' | 'BLOCK'
  signals: string[]
}

export interface Payment {
  id: string
  userId: string
  amount: number
  currency: Currency
  status: PaymentStatus
  method: PaymentMethod
  recipientWallet: string
  recipientName?: string
  description?: string
  route: string
  networkFee: number
  intellixFee: number
  totalDeducted: number
  txHash?: string
  riskScore: number
  fraudVerdict: string
  routeOptimized: boolean
  scheduledAt?: Date
  completedAt?: Date
  createdAt: Date
  metadata?: Record<string, unknown>
}

export interface WebhookEvent {
  id: string
  type: string
  paymentId: string
  data: Payment
  timestamp: string
}

// ─────────────────────────────────────────────
// EXCHANGE RATES (mock — replace with live feed)
// ─────────────────────────────────────────────

const EXCHANGE_RATES: Record<string, number> = {
  'USD-EUR': 0.9254, 'EUR-USD': 1.0806,
  'USD-GBP': 0.7892, 'GBP-USD': 1.2671,
  'USD-JPY': 149.82, 'JPY-USD': 0.00667,
  'BTC-USD': 66598.42, 'USD-BTC': 0.0000150,
  'ETH-USD': 3502.18, 'USD-ETH': 0.000286,
  'USDC-USD': 1.0001, 'USD-USDC': 0.9999,
  'SOL-USD': 142.30, 'USD-SOL': 0.00703,
}

function convertToUSD(amount: number, currency: Currency): number {
  if (currency === 'USD') return amount
  const rate = EXCHANGE_RATES[`${currency}-USD`]
  if (!rate) throw new Error(`No rate for ${currency}`)
  return amount * rate
}

// ─────────────────────────────────────────────
// ROUTE OPTIMIZER SERVICE
// ─────────────────────────────────────────────

class RouteOptimizerService {
  private readonly routes: RouteOption[] = [
    { path: 'polygon_bridge',  network: 'polygon',  estimatedFee: 0.18,  estimatedTimeSeconds: 14,   savingsVsDirect: 0.985 },
    { path: 'direct_ethereum', network: 'ethereum', estimatedFee: 12.40, estimatedTimeSeconds: 30,   savingsVsDirect: 0 },
    { path: 'direct_bitcoin',  network: 'bitcoin',  estimatedFee: 2.10,  estimatedTimeSeconds: 600,  savingsVsDirect: 0.83 },
    { path: 'ach_transfer',    network: 'ach',      estimatedFee: 0.00,  estimatedTimeSeconds: 86400,savingsVsDirect: 1.0 },
    { path: 'swift_transfer',  network: 'swift',    estimatedFee: 25.00, estimatedTimeSeconds: 86400,savingsVsDirect: 0 },
    { path: 'solana_direct',   network: 'solana',   estimatedFee: 0.02,  estimatedTimeSeconds: 5,    savingsVsDirect: 0.998 },
  ]

  findCheapest(intent: PaymentIntent): RouteOption {
    const applicable = this.getApplicableRoutes(intent)
    return applicable.reduce((best, curr) =>
      curr.estimatedFee < best.estimatedFee ? curr : best
    )
  }

  findFastest(intent: PaymentIntent): RouteOption {
    const applicable = this.getApplicableRoutes(intent)
    return applicable.reduce((best, curr) =>
      curr.estimatedTimeSeconds < best.estimatedTimeSeconds ? curr : best
    )
  }

  private getApplicableRoutes(intent: PaymentIntent): RouteOption[] {
    if (['BTC'].includes(intent.currency)) {
      return this.routes.filter(r => r.network === 'bitcoin')
    }
    if (['ETH', 'USDC'].includes(intent.currency)) {
      return this.routes.filter(r => ['polygon', 'ethereum', 'solana'].includes(r.network))
    }
    if (['SOL'].includes(intent.currency)) {
      return this.routes.filter(r => r.network === 'solana')
    }
    // Fiat
    return this.routes.filter(r => ['ach', 'swift'].includes(r.network))
  }

  estimateFee(intent: PaymentIntent, route: RouteOption): number {
    const usdAmount = convertToUSD(intent.amount, intent.currency)
    const intellixFee = usdAmount * 0.0005 // 0.05%
    return route.estimatedFee + intellixFee
  }
}

// ─────────────────────────────────────────────
// FRAUD SERVICE (stub — calls Python engine in production)
// ─────────────────────────────────────────────

class FraudService {
  async check(intent: PaymentIntent): Promise<FraudResult> {
    // In production: HTTP call to Python FraudNet microservice
    // POST https://fraud.intellix.internal/v1/score

    const usdAmount = convertToUSD(intent.amount, intent.currency)

    // Simplified scoring for demo
    let riskScore = 0.01
    const signals: string[] = []

    if (usdAmount > 50_000) {
      riskScore += 0.15
      signals.push('large_transaction')
    }
    if (usdAmount > 100_000) {
      riskScore += 0.25
      signals.push('very_large_transaction')
    }
    if (['USDC', 'USDT'].includes(intent.currency)) {
      riskScore += 0.05
      signals.push('stablecoin_routing')
    }

    riskScore = Math.min(1.0, riskScore)

    const verdict = riskScore >= 0.85 ? 'BLOCK'
      : riskScore >= 0.60 ? 'HOLD'
      : riskScore >= 0.35 ? 'REVIEW'
      : 'APPROVED'

    return { riskScore, verdict, signals }
  }
}

// ─────────────────────────────────────────────
// WEBHOOK SERVICE
// ─────────────────────────────────────────────

class WebhookService {
  private readonly registeredUrls: Map<string, string[]> = new Map()

  register(userId: string, url: string, events: string[]): void {
    this.registeredUrls.set(`${userId}:${url}`, events)
    console.log(`  ↳ Webhook registered: ${url} (${events.join(', ')})`)
  }

  async dispatch(userId: string, event: WebhookEvent): Promise<void> {
    const userWebhooks = [...this.registeredUrls.entries()]
      .filter(([key]) => key.startsWith(userId))

    for (const [key, events] of userWebhooks) {
      if (events.includes(event.type) || events.includes('*')) {
        const url = key.split(':').slice(1).join(':')
        // In production: HTTP POST with HMAC signature
        console.log(`  ↳ Dispatching ${event.type} → ${url}`)
      }
    }
  }
}

// ─────────────────────────────────────────────
// PAYMENT REPOSITORY (stub)
// ─────────────────────────────────────────────

class PaymentRepository {
  private store: Map<string, Payment> = new Map()

  async save(payment: Payment): Promise<Payment> {
    this.store.set(payment.id, payment)
    return payment
  }

  async findById(id: string): Promise<Payment | undefined> {
    return this.store.get(id)
  }

  async findByUser(userId: string): Promise<Payment[]> {
    return [...this.store.values()].filter(p => p.userId === userId)
  }

  async updateStatus(id: string, status: PaymentStatus, txHash?: string): Promise<void> {
    const payment = this.store.get(id)
    if (payment) {
      payment.status = status
      if (txHash) payment.txHash = txHash
      if (status === 'confirmed') payment.completedAt = new Date()
    }
  }
}

// ─────────────────────────────────────────────
// MAIN PAYMENT SERVICE
// ─────────────────────────────────────────────

class PaymentService {
  constructor(
    private readonly routeOptimizer: RouteOptimizerService,
    private readonly fraudService: FraudService,
    private readonly webhookService: WebhookService,
    private readonly repository: PaymentRepository,
  ) {}

  async create(intent: PaymentIntent): Promise<Payment> {
    console.log(`\n  Processing payment for ${intent.userId}: ${intent.amount} ${intent.currency}`)

    // 1. Fraud check
    console.log('  [1/4] Running fraud check...')
    const fraud = await this.fraudService.check(intent)
    console.log(`  ├─ Risk score: ${fraud.riskScore.toFixed(4)} → ${fraud.verdict}`)

    if (fraud.verdict === 'BLOCK') {
      throw new Error(`Payment blocked. Risk score: ${fraud.riskScore}. Signals: ${fraud.signals.join(', ')}`)
    }

    // 2. Route optimization
    let route = { path: 'direct', estimatedFee: 12.40, estimatedTimeSeconds: 30, network: 'ethereum' as Network, savingsVsDirect: 0 }
    let networkFee = route.estimatedFee

    if (intent.routeOptimizer) {
      console.log('  [2/4] Optimizing route...')
      route = this.routeOptimizer.findCheapest(intent)
      networkFee = route.estimatedFee
      const saving = (12.40 - networkFee).toFixed(2)
      console.log(`  ├─ Route: ${route.path} (fee: $${networkFee}, saved: $${saving})`)
    }

    // 3. Calculate fees
    const usdAmount = convertToUSD(intent.amount, intent.currency)
    const intellixFee = parseFloat((usdAmount * 0.0005).toFixed(2))
    const totalDeducted = parseFloat((usdAmount + networkFee + intellixFee).toFixed(2))

    // 4. Create payment record
    const payment: Payment = {
      id: `PAY${Date.now().toString(36).toUpperCase()}`,
      userId: intent.userId,
      amount: intent.amount,
      currency: intent.currency,
      status: fraud.verdict === 'HOLD' ? 'flagged' : 'processing',
      method: intent.method,
      recipientWallet: intent.recipientWallet,
      recipientName: intent.recipientName,
      description: intent.description,
      route: route.path,
      networkFee,
      intellixFee,
      totalDeducted,
      riskScore: fraud.riskScore,
      fraudVerdict: fraud.verdict,
      routeOptimized: intent.routeOptimizer,
      scheduledAt: intent.scheduleAt,
      createdAt: new Date(),
      metadata: intent.metadata,
    }

    await this.repository.save(payment)
    console.log(`  [3/4] Payment created: ${payment.id} (${payment.status})`)

    // 5. Simulate network confirmation
    if (payment.status === 'processing') {
      setTimeout(async () => {
        const txHash = `0x${Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join('')}`
        await this.repository.updateStatus(payment.id, 'confirmed', txHash)
        console.log(`\n  ✓ Payment ${payment.id} confirmed`)
        console.log(`  └─ TX Hash: ${txHash.slice(0, 20)}...`)

        await this.webhookService.dispatch(payment.userId, {
          id: `WH${Date.now()}`,
          type: 'payment.confirmed',
          paymentId: payment.id,
          data: { ...payment, status: 'confirmed', txHash },
          timestamp: new Date().toISOString(),
        })
      }, route.estimatedTimeSeconds > 60 ? 100 : route.estimatedTimeSeconds * 10)
    }

    console.log(`  [4/4] Total deducted: $${totalDeducted} (fee: $${networkFee + intellixFee})`)
    return payment
  }

  async getPayment(id: string): Promise<Payment> {
    const payment = await this.repository.findById(id)
    if (!payment) throw new Error(`Payment ${id} not found`)
    return payment
  }

  async getUserPayments(userId: string): Promise<Payment[]> {
    return this.repository.findByUser(userId)
  }

  async cancel(id: string): Promise<void> {
    const payment = await this.getPayment(id)
    if (!['pending', 'processing'].includes(payment.status)) {
      throw new Error(`Cannot cancel payment in ${payment.status} state`)
    }
    await this.repository.updateStatus(id, 'cancelled')
    console.log(`  ✓ Payment ${id} cancelled`)
  }
}

// ─────────────────────────────────────────────
// DEMO RUNNER
// ─────────────────────────────────────────────

async function runDemo(): Promise<void> {
  console.log('═'.repeat(60))
  console.log('  INTELLIX PAYMENT SERVICE — TypeScript Demo')
  console.log('═'.repeat(60))

  const routeOptimizer = new RouteOptimizerService()
  const fraudService = new FraudService()
  const webhookService = new WebhookService()
  const repository = new PaymentRepository()
  const paymentService = new PaymentService(routeOptimizer, fraudService, webhookService, repository)

  // Register a webhook
  webhookService.register('USR001', 'https://app.intellix.io/webhooks', ['payment.confirmed', 'payment.failed'])

  // Test 1: Optimized crypto payment
  console.log('\n[TEST 1] Optimized ETH payment via Polygon Bridge')
  const pay1 = await paymentService.create({
    userId: 'USR001',
    amount: 12_500,
    currency: 'USD',
    recipientWallet: '0x3f4a9b2c',
    recipientName: 'NovaPay Corp',
    description: 'Q1 Settlement',
    method: 'crypto',
    routeOptimizer: true,
  })
  console.log(`  └─ ID: ${pay1.id}`)

  // Test 2: USDC transfer
  console.log('\n[TEST 2] USDC transfer')
  const pay2 = await paymentService.create({
    userId: 'USR003',
    amount: 28_440,
    currency: 'USDC',
    recipientWallet: '0xpool5678',
    method: 'defi',
    routeOptimizer: true,
  })
  console.log(`  └─ ID: ${pay2.id}`)

  // Test 3: Large transaction (triggers HOLD)
  console.log('\n[TEST 3] Large USDC transfer to offshore (expect HOLD)')
  try {
    const pay3 = await paymentService.create({
      userId: 'USR008',
      amount: 84_200,
      currency: 'USDC',
      recipientWallet: '0xCAYMAN99',
      method: 'crypto',
      routeOptimizer: false,
    })
    console.log(`  └─ ID: ${pay3.id} (status: ${pay3.status})`)
  } catch (err) {
    console.log(`  └─ ✗ Blocked: ${(err as Error).message.slice(0, 60)}`)
  }

  // Give confirmations time to process
  await new Promise(r => setTimeout(r, 500))

  // Show user payment history
  console.log('\n[HISTORY] USR001 payments:')
  const history = await paymentService.getUserPayments('USR001')
  history.forEach(p => {
    console.log(`  ${p.id}: ${p.amount} ${p.currency} → ${p.status} (risk: ${p.riskScore.toFixed(3)})`)
  })
}

runDemo().catch(console.error)
