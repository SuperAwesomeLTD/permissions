import { RequireExactlyOne, MergeExclusive } from 'type-fest';

import {
  EPossession,
  TActionsList,
  TAttributes,
  TlimitOwned,
  TGrants,
  TisOwner,
  TlistOwned,
  Tid,
} from './types';

/**
 __NOTE: This class `PermissionDefinition_DOCS` is a dummy one, it is only the placeholder for docs for the real [PermissionDefinition](/miscellaneous/typealiases.html#PermissionDefinition) which is a type alias__.

 A `PermissionDefinition` (in short **PD**) is the fundamental way to define **permission rules**:

 > It grants which **Actions** (eg `approve`, `follow`) a **Role** (eg `EMPLOYEE`) can perform on a **Resource** (eg `Document`), whether on **any** Resource or only on **own** ones.

 The grants can also restrict some *Role-Action-Resource* declarations to:

 - touch only specific **attributes**, defined as an array of attributes names (eg `['title', 'price']`) & optionally glob notation (eg `'*'` or `'!confidentialNotes'`).

 - perform an action only on **OWN Resources**, where Ownership is defined as  **ownership** hooks (i.e async callbacks) that define how the give roles own an particular resource.

 __Note__ : when you use **any ownership hook**, the following rules apply:

 - you 'll need to implement `isOwner` for sure.

 - also need to implement one of `listOwned` OR `limitOwned`, but not both.

  i.e its an all or nothing, also enforced as runtime check - see the reasoning in the [FAQ](/additional-documentation/faq,-gotchas-&-caveats.html).

 __Note__: A PermissionDefinition is a loose definition, meaning that all of the props are **optional**. This is because users can use [defaults](/classes/PermissionDefinitionDefaults.html), use [shortcut syntax for grant actions](/classes/PermissionDefinition_DOCS.html#grant) etc.

 At runtime though, your complete PDs are validated thoroughly at the earliest possible - see [Principles](/additional-documentation/philosophy,-principles-&-architecture.html).

 ## Example

 ```typescript
 {
      roles: ['EMPLOYEE', 'REGISTERED_USER'],
      resource: 'document',
      descr: "I can CRUD only OWN Documents (i.e created by me)." +
             "I can read all but 'confidential' fields.",
      isOwner: async ({ user, resourceId }) => await isUserOwnerOfDocument({ user, resourceId }),
      listOwned: async user => await listOfUserOwnedDocumentIds(user),
      grant: {
        'create:own': ['*'],
        'read:own': ['*', '!confidential'],
        'update:own': ['*', '!confidential'],
        'delete:own': ['*'],
    },
  }
 ```

 */
// eslint-disable-next-line @typescript-eslint/class-name-casing
class PermissionDefinition_DOCS<TUserId extends Tid, TResourceId extends Tid> {
  /** Base PermissionDefinition, i.e without out Ownership hooks - stored in PermissionDefinitionNoOwnershipInternal - PLEASE KEEP IN SYNC

  /**
   * The name(s) of the Role we are defining (eg `['ADMIN', 'EMPLOYEE']`).
   */
  roles?: string | string[];

  /**
   * The name of the resource, eg 'document', 'comment' or 'campaign'
   */
  resource?: string;

  /**
   The Human readable description (i.e both Product/Business Owners & Developers) of the *PermissionDefinition*, roughly following a standard structure:

   `I <can | cannot> <ACTIONS> <any | own + definition> <Resource>`

   for example:

   * `I can CREATE, VIEW, EDIT or DELETE any Document`

   * `I can CREATE, VIEW, EDIT or DELETE all Documents that are created by me OR any User that I manage.`

   This is plain English and not parsable, so it can be anything, but it's good to keep it non-ambiguous and lean.
   */
  descr?: string;

  /**
   A list of actions granted (i.e CRUD operations `'read'`, `'create'`, `'delete'`, `'update'` but also anything your domain dictates such as `'like'`, `'follow'`, `'approve'` etc) that the Role can perform & the attributes allowed for each action.

   Also it can contain the Possession (after a colon), i.e whether they can perform each action only on their *own resources* or on *any resources*, for example `create:own` or `delete:any`. If an action is missing the Possession "any" or "own" then it inherits it from `possession` field of this PD which acts as the PDs default (the local one in the action overrides this the PD default). If there is no default set, it is interpreted as 'any' (reason is that 'own' requires ownership hooks).

   The format is compatible with [Access-Control action rules](https://github.com/onury/accesscontrol#actions-and-action-attributes) but can also be a shortcut syntax of a `string[]` of actions (eg `['approve', 'like', 'dislike']` in which case `possession` and `attributes` are inherited from corresponding fields in the PD (or the defaults).

   Note that by listing an action as a grant on PD, it becomes a legitimate action on your subsequent locked `build()`-ed SAPermission instance. So be careful with naming!

   You can also use the '*' for an action (eg {..., grant: {'*:own'}, ...} which will grant the Role(s) of this PD to any **known action** of this SAPermission instance.
   */
  grant?: TGrants | TActionsList;

  /**
   Acts as the *default* attributes on the PD's `grant` actions, useful when using the shortcut `string[]` for grant.


   ```typescript
   {
     attributes: ['fooProp', 'is', 'tender'],
     grant: {
       fooAction: null,
       barAction: ['bar', '!tender'],
       anotherAction: null
     }
   }
   ```

   `fooAction` will be internally represented as

   ```typescript
   {
     grant: {
       fooAction: ['fooProp', 'is', 'tender'],
       barAction: ['bar', '!tender']
       anotherAction: ['fooProp', 'is', 'tender'],
     }
   }
   ```
   */
  attributes?: TAttributes;

  /**
   Acts as the *default* possession on the PD. For example the PD:

   ```typescript
   {
     possession: EPossession.own;
     grant: {
       fooAction: ['*'],
       'barAction:any': ['*'],
       anotherAction: ['tada'],
     }
   }
   ```

   will be internally resolved as

   ```typescript
   {
     grant: {
       'fooAction:own': ['*'],
       'barAction:any': ['*'],
       'anotherAction:own': ['tada'],
     }
   }
   ```
   */
  possession?: EPossession | 'own' | 'any';

  /** Ownership hooks - stored in PermissionDefinitionWithOwnershipInternal - PLEASE KEEP IN SYNC */

  /**
   An **async function**, to determine ownership of the resource by a User that has one the Roles of this PD.

   The function should be bound to its own context and should return `true` **if User is an owner** of the particular `resourceId` queried for the particular roles, `false` otherwise.

   Must be implemented by the app developer, based on the app's business rules of what ownership means for the role(s).

   It's *optional* if the Role asked already has `isOwner` defined in another PD (for same resource etc). At the same time, we can add `isOwner` to another PD, in which case BOTH are executed when `Permit::isOwn()` is called (i.e the extending one is not shadowing the extended one). As soon as any of those returns true, `Permit::isOwn()` returns true.

   But, if `own` is used (even in one action), `isOwner` must be defined, otherwise an error is thrown at at `build()` time.
   */
  isOwner: TisOwner<TUserId, TResourceId>;

  /**
   An **async function** returning a list of owned resourceIds (i.e `number[]` or `string[]`) for users that have this Role(s).

   Like `isOwner`, it must be implemented by the app developer, based on the app's business rules of what ownership means for the role(s).

   It's mandatory to have a `listOwned` hook for roles with OWN possession, unless `limitOwn` (see below) exists. Note that and both `listOwned` and `limitOwned` CAN NOT COEXIST for a Role set & a resource.

   It is *optional* if possession is ANY or if the Role(s) being defined already have a `listOwned` defined in another PermissionDefinition for the same resource.

   Note that all unique `listOwned` hooks, of all `PermissionDefinition` found to match resource and all Roles of the user, are executed when `Permit::listOwn()` is called, and the result is the **union** of all resourceIds of all `listOwned()` calls.

   Note: This hook can become a bottleneck, if a User potentially has a huge number of owned resources. This can be solved by using

   */
  listOwned: TlistOwned<TUserId, TResourceId>;

  /**
   A **synchronous function** containing conditions, restrictions or clauses (a.k.a an ownership hook) that configures the actual *query* (or a *filter*) in an accumulating way, that is then used to filter / limit the data from the data layer (eg the DB), for users that have this Role(s).

   The purpose of `limitOwn` is to filter the resources for the given role(s) **lazily** - in contrast with `listOwn()` which aggressively fetches all owned resourceIds of the User.

   All compatible `limitOwned` functions found for a user, are composed when `Permit:limitOwn()` is called to configure the query or generate the filter that is used to filter the actual data lazily.

   See `Permit:limitOwn()` for detailed description and examples.
   */
  limitOwned: TlimitOwned<TUserId, any>;
}

/**
 This is the actual PermissionDefinition implementation, but the docs are in [PermissionDefinition_DOCS](/classes/PermissionDefinition_DOCS.html).

 Implements the ownership hooks rules.
 */
export type PermissionDefinition<
  TUserId extends Tid,
  TResourceId extends Tid
> = MergeExclusive<
  PermissionDefinitionNoOwnershipInternal,
  RequireExactlyOne<
    PermissionDefinitionWithOwnershipInternal<TUserId, TResourceId>,
    'listOwned' | 'limitOwned'
  >
>;

/**
 * @internal
 * This is an internal class - see [PermissionDefinition_DOCS](/classes/PermissionDefinition_DOCS.html)
 */
class PermissionDefinitionNoOwnershipInternal {
  roles?: string | string[];

  resource?: string;

  descr?: string;

  grant?: TGrants | TActionsList;

  attributes?: TAttributes;

  possession?: EPossession | 'own' | 'any';
}

/**
 * @internal
 * This is an internal class - see [PermissionDefinition_DOCS](/classes/PermissionDefinition_DOCS.html)
 */
class PermissionDefinitionWithOwnershipInternal<
  TUserId extends Tid,
  TResourceId extends Tid
> extends PermissionDefinitionNoOwnershipInternal {
  isOwner: TisOwner<TUserId, TResourceId>;

  listOwned: TlistOwned<TUserId, TResourceId>;

  limitOwned: TlimitOwned<TUserId, any>;
}

/**
 The optional `PermissionDefinitionDefaults` is a single object (a Partial of [`PermissionDefinition`](/classes/PermissionDefinition_DOCS.html)) whose property values are merged with each [`PermissionDefinition`](/classes/PermissionDefinition_DOCS.html) instance, if an instance's property value is missing.

 For example, in the code below:

 ```typescript
 const pdDefaults: PermissionDefinitionDefaults = { resource: 'document' };
 permissions.addDefinitions([ {PD1}, {PD2}, ..., {PDn} ], pdDefaults);
 ```

 all PDs that are missing the `resource` property, they will end up with the `{ resource: 'document' }`.
 */
export class PermissionDefinitionDefaults {
  // @todo: define with typescript's Pick & modifiers or equivalent
  roles?: string | string[];

  resource?: string; // a.k.a resourceType eg 'document'

  possession?: EPossession;

  attributes?: TAttributes;
}

export interface ICompletePermissionDefinitions<
  TUserId extends Tid,
  TResourceId extends Tid
> {
  defaults?: PermissionDefinitionDefaults;
  definitions: PermissionDefinition<TUserId, TResourceId>[];
}

/**
 @internal

 All `PermissionDefinition` are converted internally to a set of `PermissionDefinitionInternal`, after some consolidation takes place to settle defaults, remove duplicates etc.

 A `PermissionDefinitionInternal` is **strict** and **self complete**, i.e it has settled/inherited the defaults and thus nas no missing props.
 */
export class PermissionDefinitionInternal<
  TUserId extends Tid,
  TResourceId extends Tid
> {
  // @todo: define with typescript's Pick & modifiers or equivalent
  roles: string[];

  resource: string;

  descr: string;

  isOwner?: TisOwner<TUserId, TResourceId>;

  listOwned?: TlistOwned<TUserId, TResourceId>;

  limitOwned?: TlimitOwned<TUserId, any>;

  grant: TGrants;
}
