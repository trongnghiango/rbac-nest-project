export class InvalidMoneyException extends Error {
  constructor(message: string) {
    super(message);
  }
}

export class Money {
  constructor(
    private readonly amount: number,
    private readonly currency: string = 'VND',
  ) {
    if (amount < 0) {
      throw new InvalidMoneyException('Amount cannot be negative');
    }
    if (!Number.isInteger(amount)) {
      throw new InvalidMoneyException('Amount must be an integer');
    }
  }

  add(other: Money): Money {
    this.validateSameCurrency(other);
    return new Money(this.amount + other.amount, this.currency);
  }

  subtract(other: Money): Money {
    this.validateSameCurrency(other);
    if (other.amount > this.amount) {
      throw new InvalidMoneyException('Insufficient funds');
    }
    return new Money(this.amount - other.amount, this.currency);
  }

  multiply(factor: number): Money {
    return new Money(Math.round(this.amount * factor), this.currency);
  }

  getAmount(): number {
    return this.amount;
  }

  getCurrency(): string {
    return this.currency;
  }

  equals(other: Money): boolean {
    return this.amount === other.amount && this.currency === other.currency;
  }

  private validateSameCurrency(other: Money): void {
    if (this.currency !== other.currency) {
      throw new InvalidMoneyException('Currencies must match');
    }
  }
}
