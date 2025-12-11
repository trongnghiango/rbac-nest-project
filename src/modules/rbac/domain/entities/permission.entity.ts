export class Permission {
  constructor(
    public id: number | undefined,
    public name: string,
    public description?: string,
    public resourceType?: string,
    public action?: string,
    public isActive: boolean = true,
    public attributes: string = '*',
    public createdAt?: Date,
  ) {}
}
