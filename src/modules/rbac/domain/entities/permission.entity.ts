export interface PermissionProps {
  id?: number;
  name: string;
  description?: string;
  resourceType?: string;
  action?: string;
  isActive?: boolean;
  attributes?: string;
  createdAt?: Date;
}

export class Permission {
  public readonly id?: number;
  public readonly name: string;
  public readonly description?: string;
  public readonly resourceType?: string;
  public readonly action?: string;
  public readonly isActive: boolean;
  public readonly attributes: string;
  public readonly createdAt?: Date;

  constructor(props: PermissionProps) {
    this.id = props.id;
    this.name = props.name;
    this.description = props.description;
    this.resourceType = props.resourceType;
    this.action = props.action;
    this.isActive = props.isActive ?? true; // Mặc định là true nếu không truyền
    this.attributes = props.attributes ?? '*'; // Mặc định là '*'
    this.createdAt = props.createdAt;
  }
}
