import * as _ from 'lodash';
import { Permission } from 'accesscontrol';
import {
  IContext,
  IResourceItemWithId,
  IResourceItemWithOptionalId,
  IUser,
  TAttributes,
  TlimitOwned,
  TlimitOwnReduce,
  Tid,
  TisOwner,
  TlistOwned,
} from './types';

/**
An `Permit` instance represents the granted permissions for the current __User__ against a __Resource__, __Action__ & optionally __resourceId__, along with useful helpers, for async attribute picking, ownership filtering, mapping etc.

Its the result of the evaluation of [`grantPermit()`](/classes/Permissions.html#grantPermit), by applying the User to the PDs.

All the information, helpers & further querying you might require for your current request, you'll find it here.

__Note__: `Permit` constructor is private, you shouldn't instantiate one your self, just call `grantPermit()`.
*/
export class Permit<TUserId extends Tid, TResourceId extends Tid> {
  private constructor(
    /**
     The same [`IUser`](/interfaces/IUser.html) object passed in `grantPermit()`
    */
    public readonly user: IUser<TUserId>,
    /**
     The action requested (which is just the action, without possession, eg 'update').

     The Permit will tell you if its allowed for any, own etc Possessions
     */
    public readonly action: string,
    public readonly resource: string,
    public readonly resourceId: TResourceId,
    private readonly anyAcPermission: Permission,
    private readonly ownAcPermission: Permission,

    /**
     * All `isOwner()` functions collected from PermissionDefinitions
     */
    private readonly _isOwners: TisOwner<TUserId, TResourceId>[],
    /**
     * All `listOwned()` functions collected from PermissionDefinitions
     */
    private readonly _listOwneds: TlistOwned<TUserId, TResourceId>[],
    private readonly _limitOwneds: TlimitOwned<TUserId, any>[],
    private readonly _limitOwnReduce: TlimitOwnReduce<TUserId, any>
  ) {}

  private _resourceIdOwnPermissionGranted = true;

  private set resourceIdOwnPermissionGranted(v: boolean) {
    this._resourceIdOwnPermissionGranted = v;
  }

  /**
   * Whether user is granted access to ANY resource.
   */
  public get anyGranted(): boolean {
    return this.anyAcPermission.granted;
  }

  /**
   Whether user is granted access to a) OWN resources in general OR b) the particular `resourceId` (if provided).
   Note that if `anyGranted === true`, then `ownGranted` will also be `true`.
   */
  public get ownGranted(): boolean {
    return this._resourceIdOwnPermissionGranted && this.ownAcPermission.granted;
  }

  /**
   The list of attributes the User can access on ANY resource.

   Note: its more convenient to use `.attributes()`

   If the user has NO 'any' access (hence only OWN), it will be [] to signify that no 'any' access was granted.
  */
  public get anyAttributes(): TAttributes {
    return this.anyAcPermission.attributes;
  }

  /**
   The list of attributes the User can access on OWN resources.
   Note: its more convenient to use `.attributes()`

   <br>

   If the user has NO 'own' access:

   * if they have 'any' access, then `ownAttributes` will be equal to `anyAttributes`, since there is no specific `own` access defined

   * if they dont have 'any' access, then it will be [].
   */
  public get ownAttributes(): TAttributes {
    return this.ownAcPermission.attributes;
  }

  /**
   * The calculated property `granted` is a shortcut helper that grants access:
   *
   * a) if either `anyGranted` or `ownGranted` is true, when `resourceId` is NOT KNOWN at `grantPermit()` query time.
   *   Note that its up to the library user to check `anyGranted` before granting access to a any specific `resourceId` later on, or to ask `isOwn(resourceId)` otherwise.
   *
   * b) if ONLY `ownGranted` is true, but `resourceId` is known and actually owned by the user. The `grantPermit()` call has already calculated the correct value of `ownGranted` if `resourceId` was passed to the call.
   *
   * Note that if `anyGranted` is true, then the `ownGranted` is also always true, irrespective of the value of `resourceId` passed to `grantPermit()`. Use `isOwn()` to find out if the resource is really owned.
   */
  public get granted(): boolean {
    return this.resourceId ? this.ownGranted : this.anyGranted || this.ownGranted;
  }

  /**
   * If action is granted on resource for user, irrespective of resourceId (if passed)
   */
  public get grantedAction(): boolean {
    return this.anyGranted || this.ownAcPermission.granted;
  }

  /**
  Call `isOwn(resourceId)` to see if the granted User is the Owner of the particular `resourceId`.

  Note the difference between `Permit::isOwn` and the PermissionDefinition `isOwner`:

  `Permit::isOwn` is composed from all the `isOwner` functions in PermissionsDefinitions that apply to this User.

  It already has the `user` & `resource` baked in, so we only need to pass `resourceId`.

  If any PermissionDefinitions `isOwner() === true` is found then it returns true, otherwise it returns `false`.

  __Notes__

   If the User has no "own" grant for the Action against the Resource, it still makes sense to call it:

   Assume a `PermissionDefinition`:

   ```js
    {
      roles: ['EMPLOYEE'],
      isOwner: async (resourceId) => [1,2,3].includes(resourceId),
      grant: {
       'read:any': ['id', 'title'],
       'read:own': ['id', 'title', 'confidential'],
      }
    }
   ```

  and we request a `Permit` for `EMPLOYEE read document`, we should still be able to know which documents are OWN cause we might want to _.pick:

   - ANY document with any `['id', 'title']`

   - OWN documents with `['id', 'title', 'confidential']`, a permission we obtained from the `read:own` grant

  @param resourceId The ID of the resource, eg `123`
  */
  public async isOwn(resourceId: TResourceId): Promise<boolean> {
    for (const isOwner of this._isOwners)
      if (
        await isOwner({
          user: this.user,
          resourceId,
        })
      )
        return true;

    return false;
  }

  /**
   Returns an array of the `resourceIds` owned by the User, that can be used to filter the resource items the User can act on.

   __How to Use__

   In your app, you can do something like:

   ```typescript
      const ownedDocumentIds = await permit.listOwn();
      const query = `SELECT FROM document WHERE document.id in (${ownedDocumentIds.join(',')})`; // but if using Postgres/TypeORM be careful of issues like https://github.com/typeorm/typeorm/issues/2195#issuecomment-492991247)
   ```

   Note: the difference between `Permit::listOwn` and `PermissionDefinition::listOwned`:

     `Permit::listOwn` is a dynamically composed function of the potentially different `isOwner` functions attached to different `PermissionsDefinitions` that apply to this User.

   The composed function calls all the `listOwned` found for the user & __returns the UNION of all resourceIds__.

   __Notes__

   a) When `anyGranted = true`

   If `anyGranted` is true we usually expect the app to NOT filter the resources, since our User can access all documents. It is the  responsibility of the userland's app, to check for `permit.anyGranted === true` and to avoid applying filtering on the DB query etc.

   BUT `listOwn()` might still make sense, in case we want to handle differently user's own documents. In this case, if no `listOwned` is defined, it returns an empty [].

   b) The `listOwn()` callback that returns a list of own ids is not scalable, if we potentially have too many (eg hundred thousand or millions) of owned resourceIds for a user and it could break the service (i.make it too slow).

   The reason is that the callback is required to prefetch ALL ids of the resource owned by that user (in memory) and then probably use them to build an "IN (...ownedIds)" type query. And usually the service will go ahead and fetch only a small subset of those (eg a page of 10 or 50 resources).

   For these reasons, you should use the `limitOwn()` hook - see below. Also in the near future, this hook will probably be DEPRECATED.
  */
  public async listOwn(): Promise<TResourceId[]> {
    if (!this.grantedAction)
      throw new Error(
        'SA-Permissions: `permit.listOwn()` called but permit.grantedAction is false'
      );

    if (!this.isListOwnSupported())
      throw new Error(
        'SA-Permissions: `permit.listOwn()` called but its not supported for this Permit'
      );

    const ownIds: TResourceId[] = [];
    for (const listOwned of this._listOwneds) {
      const resourceIds = await listOwned(this.user);
      ownIds.push(...resourceIds);
    }

    return _.uniq(ownIds);
  }

  public isListOwnSupported() {
    return !_.isEmpty(this._listOwneds);
  }

  /**
   Configures the actual __query__ (or generates the __filter__) used to fetch the data from the data layer (eg the DB), using the conditions/restrictions imposed by the roles of the user, as these are defined in `limitOwned` ownership hooks in `PermissionDefinitions`.

   The purpose of `limitOwn` is to allow the filtering of resources owned by the User __lazily__ - in contrast with `listOwn()` which aggressively fetches all owned resourceIds of the User.

   In other words, it configures (OR successively builds) a __filter__ or __query__, but doesn't actually perform the filtering it self. Think of it as composing a function to pass to `Array.filter` or adding some `orWhere` clauses to an ORM query, but not actually executing the query.

   It is agnostic of the ORM/DB engine used. This can work by passing an arbitrary `context` value (can be an Object, Array or any other accumulator of your choice) that holds the successive clauses, predicates etc of the owned restrictions defined as `limitOwned` hooks. For example the `context` in TypeORM could be a the `query` or a `subquery` object, before it has been executed.

   __Note__: the difference between `Permit::limitOwn` and `PermissionDefinition::limitOwned`: The `Permit::limitOwn` is a dynamically composed function of the potentially different `PermissionDefinition::limitOwned` functions attached to different `PermissionsDefinitions` that apply to this User (based on the roles user carries).

   By default, to reduce all `PermissionDefinition::limitOwned` together, it calls all unique `limitOwned` functions found for the user, passing the `user` and the `context` value at each call and retrieving `context` back as the accumulator of that call.   Finally it returns the resulting `context` value, whatever that might be. You can change this behavior, by using your own `limitOwnReduce`, passed at the Permissions constructor.

  __Considerations__

   - You must construct your `limitOwned` functions in the `PermissionsDefinitions`, using __OR logic__ of the WHERE clauses or predicates, instead of an __AND logic__.

     This is because for example a User that has both `EMPLOYEE` and `EMPLOYEE_MANAGER` roles, the resulting query should include all `EMPLOYEE_MANAGER` plus the `EMPLOYEE` filtered items (i.e their __union__).

     If our subquery was build with __AND logic__, then only the items that satisfy both constraints would be filtered (ie. their __intersection__).

   - You must accumulate the existing `context` value(s), in the `context` value than you return from each `limitOwned` hook and then perhaps compose the final one from the `context` returned from the `limitOwn` call.

   Depending on the context you choose, you may provide __your own__ `limitOwn()` version by passing a `limitOwnReduce` in the `Permissions` constructor - see below.

   A TypeORM `query` object is the ideal context & use case for the default reduce logic of `limitOwn`. The `query` accumulates all calls to `andWhere` etc in its own self. Assuming a TypeORM app, with `PermissionDefinitions` like

   ```js
     [
       {
         ...
         roles: 'RoleA'
         limitOwned: (user, query) => query.orWhere(`"someField" = '${user.someField}'`);
       },
       {
         ...
         roles: 'RoleB'
         limitOwned: (user, query) => query.orWhere(`"otherField" = '${user.otherField}'`);
       }
     ]
   ```

   you can simply do something like this in you app's code:

   ```js
   query.andWhere(new Brackets(qb => permit.limitOwn(qb)));
   ```
   hence for a User with both RoleA & RoleB the resulting query will be augmented with a WHERE clause like

   ```sql
   SELECT ...fields... FROM resource
   WHERE ...existing where clauses....
   AND ("someField" = 'someValue' OR "otherField" = 'otherValue') -- <<< the WHERE clause augmented by limitOwn()
   ```

   But if you were returning a function predicate, make sure your return something that accumulates the existing ones in the `context` and in the final call you take all into account.

   There are many ways to achieve this, like functional composition or a simple collection, with or without context and with or without using `limitOwnReduce`.

   See [Example 5 with lodash & context and Example 6 for an even simpler one](/additional-documentation/detailed-usage-&-examples.html).
  */
  public limitOwn<Tctx>(context?: IContext<Tctx>): any {
    if (!this.grantedAction)
      throw new Error(
        'SA-Permissions: `permit.limitOwn()` called but permit.grantedAction is false'
      );

    if (this._limitOwnReduce)
      return this._limitOwnReduce({
        user: this.user,
        limitOwneds: this._limitOwneds,
        context,
      });

    return this._limitOwneds.reduce(
      (contextAccumulator, limitOwned) =>
        limitOwned({ user: this.user, context: contextAccumulator }),
      context
    );
  }

  /**
  Helper that returns the attributes the __User__ is permitted to use for the current __Resource__ & __Action__.

  By optionally passing a `resourceId` of a particular resource item, we get the effective `anyAttributes` OR `ownAttributes` that the particular User, depending on the __ownership of the `resourceId`__, according to this Permit's `isOwner` result.

  It saves you having to `const attributes = await permit.isOwner(resourceId) ? permit.ownAttributes : anyAttributes`

  @param resourceId optional
  */
  public async attributes(resourceId?: TResourceId): Promise<TAttributes> {
    if (!resourceId) return this.anyAttributes;
    return (await this.isOwn(resourceId)) ? this.ownAttributes : this.anyAttributes;
  }

  /**
   Helper to perform a `_.pick`-like operation of the allowed attributes from an object, based on `permit.attributes()`.

   It checks for `isOwn` on the resource appropriately and picks attributes based on attributes defined on `own` or `any` permissions.
   If user has no access to this resource at all, it returns an empty object.

   @param resourceItem an object possibly with an `id` attribute to be used as the resourceId and check for ownership.
   @param resourceIdOrOwn optional, 2 uses:

      - if a `Tid` is passed it ignores `resourceItem.id` and uses `resourceId` for the internal `isOwn()` check.

      - If `true` or `false` is passed, it overrides check and picks "own" or "any" attributes respectively.

  */
  public async pick<
    TSomeResourceItemWithOptionalId extends IResourceItemWithOptionalId<TResourceId>
  >(
    resourceItem: TSomeResourceItemWithOptionalId,
    resourceIdOrOwn: TResourceId | boolean = resourceItem.id
  ): Promise<Partial<TSomeResourceItemWithOptionalId>> {
    if (!resourceIdOrOwn) return this.anyAcPermission.filter(resourceItem);

    return resourceIdOrOwn === true || (await this.isOwn(resourceIdOrOwn))
      ? this.ownAcPermission.filter(resourceItem)
      : this.anyAcPermission.filter(resourceItem);
  }

  /**
  Given an array of `resourceItems`, it filters & maps to an array of `_.pick`-ed items, allowing only:

   - the allowed items to pass through (eg only own, if only own possession is granted).

   - the allowed attributes in each item, based on ownership (if needed).

   @param resourceItems An array of `resourceItems` (eg an array of documents).
         All resourceItems MUST have an 'id' property for the ownership check.

   @return a filtered array of allowed items, each only with allowed attributes, i.e a `Promise<Partial<TSomeResourceItemWithId>[]>`.
  */
  public async filterPick<TSomeResourceItemWithId extends IResourceItemWithId<TResourceId>>(
    resourceItems: TSomeResourceItemWithId[]
  ): Promise<Partial<TSomeResourceItemWithId>[]> {
    const resultItems: Partial<TSomeResourceItemWithId>[] = [];
    for (const resourceItem of resourceItems)
      if (this.anyAcPermission.granted) {
        resultItems.push(await this.pick(resourceItem));
      } else if (await this.isOwn(resourceItem.id)) {
        resultItems.push(await this.pick(resourceItem, true));
      }

    return resultItems;
  }

  /**
   Given an array of `resourceItems` with an `id` property (eg an array of Document objects), it maps to a new Array where:

   - first each item becomes a `projectedItem` (i.e mapped through `projectTo`).

   - then each `projectedItem` is `Permit.pick`-ed , allowing only the allowed attributes in each item, based on ownership of each item.

   @param resourceItems An array of `resourceItems`.
          Each needs to have an 'id' property for the ownership check.

   @param projectTo A sync or async function `(item:T) => any` projecting an item to any (like `Array.map)`
   */
  public async mapPick<TSomeResourceItemWithId extends IResourceItemWithId<TResourceId>>(
    resourceItems: TSomeResourceItemWithId[],
    projectTo: (item: TSomeResourceItemWithId) => any = _.identity
  ): Promise<Partial<TSomeResourceItemWithId>[]> {
    const resultItems: Partial<TSomeResourceItemWithId>[] = [];
    for (const resourceItem of resourceItems) {
      const projectedItem = await projectTo(resourceItem);
      resultItems.push(await this.pick(projectedItem));
    }

    return resultItems;
  }
}
