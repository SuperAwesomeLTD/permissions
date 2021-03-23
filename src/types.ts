/**
 * An Id in your system, can be either `number` or `string` (eg a UUID).
 */
 type TnumberOrString = number | string;
 export type Tid = TnumberOrString extends number ? number : string;

 export type TJson = string | number | boolean | null | TJson[] |{ [key: string]: TJson };

/**
  All the info we need to know about a User, for example:

  ```typescript
  const user: IUser = { id: 123, roles: ['ADMIN'] };
  ```

  If your user.id is of type string:

  ```typescript
  const user: IUser<string> = { id: 'abc123', roles: ['ADMIN'], anyOtherField: 'foo' };
  ```

  If you're on vanilla JavaScript worry not: just use number or string for id and you're fine.
*/
export interface IUser<TUserId extends Tid> {
  id: TUserId;
  roles: string[];
  [key: string]: TJson;
}

/**
 * Checks if the user value is a correct [`IUser` type](/interfaces/IUser.html)
 *
 * @param user the user object to test
 */
export const isValidIUser = <TUserId extends Tid>(user: IUser<TUserId>) =>
  !!user &&
  ['number', 'string'].includes(typeof user.id) &&
  Array.isArray(user?.roles) &&
  user.roles.every((role) => typeof role === 'string');

/**
 * @internal
 */
export interface IResourceItemWithId<TResourceId extends Tid> {
  id: TResourceId;
  [key: string]: TJson;
}

/**
 * @internal
 */
export interface IResourceItemWithOptionalId<TResourceId extends Tid> {
  id?: TResourceId;
  [key: string]: TJson;
}

/**
 The interface of the [`listOwned` ownership hook](/classes/PermissionDefinition_DOCS.html#listOwned).

 Should return an array of ids (see [`Tid`](/miscellaneous/typealiases.html#Tid) eg `[1, 2, 3]` or `['abc123', 'def456']`.

  Example:
 ```js
   async (user) => documentService.findWhere({ createdBy: user.id })
 ```
 */
export type TlistOwned<TUserId extends Tid, TResourceId extends Tid> = (
  user: IUser<TUserId>
) => Promise<TResourceId[]>;

// Used to signify where `context` should be returned in limitOwn() & limitOwned hooks
export type IContext<Tctx = any> = Tctx;

/**

 The interface of the [`limitOwned` ownership hook](/classes/PermissionDefinition_DOCS.html#limitOwned).

 See [`Permit.limitOwn()`](/classes/Permit.html#limitOwn) and [Examples 5 & 6](/additional-documentation/detailed-usage-&-examples.html) for how it is used in practice.

 __Notes__:

 The `context` is of type any (IContext is just an alias for semantics).

 Its up to the user what the context is (and how you add and retrieve data from it).

 For instance, in an ORM scenario (consider TypeORM as an example) it could be your `query` or `subquery` object, to which you subsequently add `orWhere` expressions.

 In a collection (eg array) filtering example, it might be just a bunch of filter functions that you accumulate in an array (i.e the `context`) and then somehow compose (eg with _.overSome).
 */
export type TlimitOwned<TUserId extends Tid, Tctx = any> = ({
  user,
  context,
}: {
  user?: IUser<TUserId>;
  context?: IContext<Tctx>;
}) => IContext<Tctx>;

/**
 The interface of the `limitOwnReduce` you can pass to override the built in `permit.limitOwn()` implementation.

 See [Example 6](/additional-documentation/detailed-usage-&-examples.html) for how it is used in practice.
 */
export type TlimitOwnReduce<TUserId extends Tid, Tctx = any> = ({
  user,
  limitOwneds,
  context,
}: {
  user: IUser<TUserId>;
  limitOwneds: TlimitOwned<TUserId, Tctx>[];
  context?: IContext<Tctx>;
}) => any;

/**
 The interface of the [`isOwner` ownership hook](/classes/PermissionDefinition_DOCS.html#isOwner).

 Should return `true` if `user` is owner of the `resourceId`, false otherwise - example:

 ```js
   async ({user, resourceId}) => (await documentService.findById(resourceId).createdBby === user.id;
 ```
*/
export type TisOwner<TUserId extends Tid, TResourceId extends Tid> = ({
  user,
  resourceId,
}: {
  user: IUser<TUserId>;
  resourceId: TResourceId;
}) => Promise<boolean>;

/**
 Eg `['*', '!price', '!confidential']`
 */
export type TAttributes = string[];

/**
 The "light" array of actions (and optional possession) that we can assign to `PermissionDefinition.grant`, granting these **actions**.

 Internally all actions will inherit by default:

 - the **attributes** of `PermissionDefinition.attributes` or default to `['*']`.

 - the **possession** of `PermissionDefinition.possession` or default to `any`.

 Example:

 ```js
 {
    // a PermissionDefinition object
    ...
    grants: ['read', 'update:own', 'like:any', 'follow']
    ...
 }
 ```

 Also see [`TGrants`](/miscellaneous/typealiases.html#TGrants)
 */
export type TActionsList = string[];

/**
 The "full" object we can assign to `PermissionDefinition.grant`, granting **actions** and their corresponding **attributes**:

 ```js
 {
    'read': ['*'],
    'read:own': ['*'],
    'read:any': ['*', '!price', '!confidential'],
    'delete:own': ['*'],
    ...
 }

 ```

 __Note__: actions optionally accept possession "any" or "own" after the colon. Internally all actions missing the possession part, will inherit the **possession** of `PermissionDefinition.possession` or default to `any`.

 Also see [`TActionsList`](/miscellaneous/typealiases.html#TActionsList)
 */
export type TGrants = { [grantAction: string]: TAttributes };

export enum EPossession {
  own = 'own',
  any = 'any',
}

/**
 The object that you pass to [permissions.grantPermit()](/classes/Permissions.html#grantPermit).

 Expresses the "can **User** do **action** on **resource** [and optionally **resourceId**]".

 See [Basic Usage](/additional-documentation/basic-usage.html)
 */
export class GrantPermitQuery<TUserId extends Tid, TResourceId extends Tid> {
  /**
   A user object with at least `{id, roles}`
   */
  user: IUser<TUserId>;

  /**
   The action name, eg `'update'`.
   __Note__: it **does NOT accept possession** (eg `update:own`), the `permissions.grantPermit()` call always checks for both.
   */
  action: string;

  /**
   The name of the resource, eg `'document'`. It must be a valid resource, defined in your `PermissionDefinitions` or you'll get a runtime error.
   */
  resource: string;

  /**
   The unique identifier (ID) of a specific resource for which access is queried.

   It's optional:

    * if not passed it only checks for general access to the resource. You can always call `permit.isOwn(resourceId)` at any later stage on that Permit.

   * if passed, it actually calls `permit.isOwn()` for you.
   */
  resourceId?: TResourceId;
}
