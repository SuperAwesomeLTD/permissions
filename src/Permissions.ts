// tslint:disable:prefer-const
// 3rd party
import * as _ from 'lodash';
import * as _f from 'lodash/fp';
import { diff } from 'json-diff';
import { AccessControl, IQueryInfo, Permission } from 'accesscontrol';
// own
import { AccessControlRe } from 'accesscontrol-re';
import {
  EPossession,
  GrantPermitQuery,
  isValidIUser,
  Tid,
  TisOwner,
  TlimitOwned,
  TlimitOwnReduce,
  TlistOwned,
} from './types';
import {
  buildAccessControl,
  deleteEmptyArrayKeys,
  hasSomeOwnGrant,
  stringify,
  projectPDWithDefaultsToInternal,
} from './utils';
import { consolidatePermissionDefinitions } from './consolidations';
import { Permit } from './Permit.class';
import {
  PermissionDefinition,
  PermissionDefinitionDefaults,
  PermissionDefinitionInternal,
} from './PermissionDefinitions';
import { getLogger } from './logger';

/**
 The options passed at the `Permissions` constructor
 */
export interface IPermissionsOptions<
  TUserId extends Tid,
  TResourceId extends Tid
> {
  permissionDefinitions?:
    | PermissionDefinition<TUserId, TResourceId>
    | PermissionDefinition<TUserId, TResourceId>[];

  permissionDefinitionDefaults?: PermissionDefinitionDefaults;

  limitOwnReduce?: TlimitOwnReduce<TUserId, any>;
}

/**
 The main class - see [Basic Usage](/additional-documentation/basic-usage.html)
*/
export class Permissions<TUserId extends Tid, TResourceId extends Tid> {
  private _permissionDefinitionsInternal: PermissionDefinitionInternal<Tid, Tid>[] = [];

  private _accessControl: AccessControl;

  private _acre: AccessControlRe;

  private _rolesNotFound = {};

  private roles: string[];

  private _limitOwnReduce: TlimitOwnReduce<TUserId, any>;

  private _isBuilt = false;

  constructor({
    permissionDefinitions,
    permissionDefinitionDefaults,
    limitOwnReduce,
  }: IPermissionsOptions<TUserId, TResourceId> = {}) {
    this._limitOwnReduce = limitOwnReduce;
    this.addDefinitions(permissionDefinitions || [], permissionDefinitionDefaults);
  }

  public addDefinitions(
    permissionDefinitions:
      | PermissionDefinition<TUserId, TResourceId>
      | PermissionDefinition<TUserId, TResourceId>[],
    permissionDefinitionDefaults: PermissionDefinitionDefaults = {}
  ) {
    this.ensureHasNotBuild();

    if (!permissionDefinitions)
      throw new Error(
        `SA-Permissions: in addDefinitions(), invalid permissionDefinitions: ${stringify(
          permissionDefinitions
        )}`
      );
    if (!_.isArray(permissionDefinitions)) permissionDefinitions = [permissionDefinitions];

    const ipdsToAdd = permissionDefinitions.map(
      projectPDWithDefaultsToInternal(permissionDefinitionDefaults)
    );

    // sanity checks before adding ipds
    _.each(ipdsToAdd, (ipdToAdd, ipdToAddIdx): any => {
      // if we are trying to redefine a role+resource+action:possession
      // with DIFFERENT attributes (i.e non-strict) throw as its very dangerous!
      const nonStrictDuplicatePds = this.filterPDsWithDuplicateGrantActions(ipdToAdd);

      if (!_.isEmpty(nonStrictDuplicatePds)) {
        const firstConflictingAction = _.findKey(
          ipdToAdd.grant,
          (attributes, action) => !!nonStrictDuplicatePds[0].grant[action]
        );
        throw new Error(
          `SA-Permissions: InvalidPermissionDefinitionError: addDefinitions() redefining action error.
            Action: "${firstConflictingAction}"
            Action Attributes: ${stringify(ipdToAdd.grant[firstConflictingAction])}
            While adding PD: ${stringify(ipdToAdd)}
            Conflicted with PD: ${stringify(nonStrictDuplicatePds[0])}`
        );
      }

      // if we are trying to redefine a role+resource+action:possession
      // even with SAME different attributes (i.e very strict) warn as obsolete!
      const strictDuplicatePds = this.filterPDsWithDuplicateGrantActions(ipdToAdd, true);

      if (!_.isEmpty(strictDuplicatePds)) {
        const firstConflictingAction = _.findKey(
          ipdToAdd.grant,
          (attributes, action) => !!strictDuplicatePds[0].grant[action]
        );
        getLogger().warn(
          `addDefinitions() redefining action in a PD with same attributes is obsolete:`,
          {
            action: firstConflictingAction,
            attributes: ipdToAdd.grant[firstConflictingAction],
            permissionDefinition: ipdToAdd,
          }
        );
      }

      if (hasSomeOwnGrant(ipdToAdd)) {
        const isOwnerFound = !!ipdToAdd.isOwner;
        let listOwnedFound = !!ipdToAdd.listOwned;
        let limitOwnedFound = !!ipdToAdd.limitOwned;

        // on this PD
        if (listOwnedFound && limitOwnedFound)
          throw new Error(
            `SA-Permissions: in addDefinitions() found BOTH "listOwned" & "limitOwned" callbacks in the added PermissionDefinition. Use one or the other, but not both. PermissionDefinition = ${JSON.stringify(
              permissionDefinitions[ipdToAddIdx],
              null,
              2
            )}`
          );

        // It has some OWN Grant, but no owner hooks found, throw
        if (!isOwnerFound || (!listOwnedFound && !limitOwnedFound)) {
          throw new Error(
            `SA-Permissions: in addDefinitions() PermissionDefinition has 'own' action but no ${
              !isOwnerFound ? '"isOwner"' : '"listOwned" nor "limitOwned"'
            } callbacks are there. PermissionDefinition = ${stringify(ipdToAdd)} `
          );
        }

        // check all for same resource as ipdToAdd
        let conflictedPD;
        for (const opd of this._permissionDefinitionsInternal) {
          if (ipdToAdd.resource === opd.resource) {
            listOwnedFound = listOwnedFound || !!opd.listOwned;
            limitOwnedFound = limitOwnedFound || !!opd.limitOwned;
          }
          if (listOwnedFound && limitOwnedFound) {
            conflictedPD = opd;
            break;
          }
        }
        if (listOwnedFound && limitOwnedFound)
          throw new Error(
            `SA-Permissions: in addDefinitions() found BOTH "listOwned" & "limitOwned" callbacks in some PermissionDefinition for resource "${
              ipdToAdd.resource
            }". Use one or the other, but not both.
            Adding PD: ${stringify(permissionDefinitions[ipdToAddIdx])}
            Conflicted with PD: ${stringify(conflictedPD)}`
          );
      }

      this._permissionDefinitionsInternal.push(ipdToAdd); // all ok, add it!
    });
  }

  /**
   * Check is this Permissions instance has been built (so no more .addDefinitions() allowed)
   */
  public get isBuilt(): boolean {
    return this._isBuilt;
  }

  public build() {
    this._isBuilt = true;
    if (this._acre) return this;
    [this._accessControl, this._acre] = buildAccessControl(this._permissionDefinitionsInternal);
    this.roles = this.getRoles();
    return this;
  }

  /**
   The `grantPermit()` is the way to *query* the Permissions instance for granting permissions to a User.

   The method responds with an instance of [Permit](/classes/Permit.html) that holds all known information about the queried **user**, **resource** and **action**.

   In short, the question is "can some of `user.roles` perform `action` either a) on **any** `resource` or b) on an **own** `resource` (AND the specific `resourceId` if passed)?

   We are checking all roles for both **any** & **own**, while collecting all `isOwner` & `listOwned` and feed all known information into a **Permit** object.

   @return Promise<Permit> a Promise of a [Permit](/classes/Permit.html) instance.
   */
  public async grantPermit({
    // <TUserId extends Tid, TResourceId extends Tid>
    user,
    action,
    resource,
    resourceId,
  }: GrantPermitQuery<TUserId, TResourceId>): Promise<Permit<TUserId, TResourceId>> {
    this.ensureHasBuild();
    if (!isValidIUser(user))
      throw new Error(
        'SA-Permissions: at grantPermit(), user is not a valid `interface IUser {id: TId; roles: string[];}`'
      );

    if (!this.getResources().includes(resource))
      throw new Error(`SA-Permissions: at grantPermit(), Invalid resource: "${resource}"`);

    if (action.split(':').length > 1)
      throw new Error(
        `SA-Permissions: at grantPermit(), Invalid action structure: "${action}". The colon ":" in the action is not allowed on grantPermit() and you must NOT specify ":own" or ":any" after the action at it. SA-Permissions always returns a Permit that checks for both any & own.`
      );

    let acPermission: Permission; // = { granted: false } as any;
    let anyAcPermission: Permission;
    let ownAcPermission: Permission;
    // The `Permit` values
    const isOwners: TisOwner<TUserId, TResourceId>[] = [];
    const listOwneds: TlistOwned<TUserId, TResourceId>[] = [];
    const limitOwneds: TlimitOwned<any, TUserId>[] = [];

    // 2 passes: check all EPossession against all roles.
    // if any permissions.granted is true, granted is true
    //  but continue to gather all permissions.attributes, isOwner & listOwned
    for (const queryPossession of [EPossession.any, EPossession.own]) {
      getLogger().debug('grantPermit: possession', { possession: queryPossession });

      const unknownRoles = _.difference(user.roles, this.roles);
      const roles = _.without(user.roles, ...unknownRoles);

      _.each(unknownRoles, (rl) => {
        if (!this._rolesNotFound[rl]) {
          this._rolesNotFound[rl] = true;
          getLogger().warn(
            `SA-Permissions(): at grantPermit(), role not found: ${rl} (will not warn again about this role)`
          );
        }
      });

      const queryInfo: IQueryInfo = {
        role: roles,
        action: `${action}:${queryPossession}`,
        resource,
      };

      try {
        acPermission = this._acre.permission(queryInfo);
      } catch (error) {
        // @todo: handle
        throw error;
      }

      getLogger().debug('grantPermit: this._accessControl.permission(queryInfo)', {
        queryInfo,
        'permission.granted': acPermission.granted,
        'permission.attributes': acPermission.attributes,
      });

      switch (queryPossession) {
        case EPossession.any: {
          anyAcPermission = acPermission;
          break;
        }

        case EPossession.own: {
          ownAcPermission = acPermission;

          if (ownAcPermission.granted) {
            const matchingCpds = _.filter(this._permissionDefinitionsInternal, (pd) => {
              return (
                _.some(pd.roles, (pdRole) => user.roles.includes(pdRole)) &&
                (resource === pd.resource || pd.resource === '*') &&
                (!!(pd?.grant || {})[`${action}:${EPossession.own}`] ||
                  !!(pd?.grant || {})[`*:${EPossession.own}`] ||
                  !!(pd?.grant || {})[`${action}:${EPossession.any}`] ||
                  !!(pd?.grant || {})[`*:${EPossession.any}`])
              );
            });

            // prettier-ignore
            if (!anyAcPermission.granted && _.isEmpty(matchingCpds))
              throw new Error(
                `SA-Permissions: own access granted but no matching PermissionDefinitions found: ` +
                `${stringify({ user, action, resource })}`,
              );

            _.each(matchingCpds, (cpd) => {
              const { isOwner, listOwned, limitOwned } = cpd;
              if (isOwner) isOwners.push(isOwner as any);
              if (listOwned) listOwneds.push(listOwned as any);
              if (limitOwned) limitOwneds.push(limitOwned as any);
            });
          }
          break;
        }

        default:
          throw new Error(
            `SA-Permissions::grantPermit: invalid EPossession in queryPossession "${queryPossession}"`
          );
      }
    }

    const permit = new (Permit as any)( // constructor is best kept private, only we should use it!
      user,
      action,
      resource,
      resourceId,
      anyAcPermission,
      ownAcPermission,
      _.uniq(isOwners),
      _.uniq(listOwneds),
      _.uniq(limitOwneds),
      this._limitOwnReduce
    );

    // prettier-ignore
    if (!anyAcPermission.granted && ownAcPermission.granted) {
      // The following checks SHOULD NOT be needed, they should be caught at the addDefinitions() call. Please report to authors if you encounter them.
      const createError = (butDetail: string) =>
        new Error(`SA-Permissions: grantPermit() "OWN" access granted but ${butDetail
        }. The error should have been caught at addDefinitions() call, please report to authors. GrantPermitQuery = ${
          stringify({ user, action, resource, resourceId })}`);

      if (_.isEmpty(isOwners)) throw createError('no "isOwner" ownership hook found');
      if (_.isEmpty(listOwneds) && _.isEmpty(limitOwneds)) throw createError('no "listOwned" nor "limitOwned" ownership hooks found');
      if (!_.isEmpty(listOwneds) && !_.isEmpty(limitOwneds)) throw createError('found BOTH "listOwned" & "limitOwned" ownership hooks. Use one or the other, but not both');

      if (resourceId) (permit as any).resourceIdOwnPermissionGranted = await permit.isOwn(resourceId);
    }

    return permit as Permit<TUserId, TResourceId>;
  }

  // some helpers
  public getRoles(): string[] {
    this.ensureHasBuild();
    return this._acre.getRoles();
  }

  public getResources(): string[] {
    this.ensureHasBuild();
    return this._acre.getResources();
  }

  public getActions(): string[] {
    this.ensureHasBuild();
    return this._acre.getActions();
  }

  /**
   * Returns a deep clone of [`AccessControl#getGrants()`](https://onury.io/accesscontrol/?api=ac#AccessControl#getGrants) (which according to its docs `Gets the internal grants object that stores all current grants.`), but omitting empty arrays eg `'rollover:any': []`.
   *
   * @see https://onury.io/accesscontrol/?api=ac#AccessControl#getGrants
   */
  public getGrants(): object {
    // @todo: typings
    this.ensureHasBuild();
    // delete empty arrays, eg `'rollover:any': []` cause they are useless & break our `compare()`
    return deleteEmptyArrayKeys(_.cloneDeep(this._accessControl.getGrants()));
  }

  public compare(permissions1: Permissions<any, any>, permissions2: Permissions<any, any> = this) {
    return diff(permissions1.getGrants(), permissions2.getGrants());
  }

  // Grab accessControl.getGrants(), BUT delete all empty / denied grants that

  /**
   Returns a list of the `PermissionDefinition` objects stored in this instance, with optional filtering & consolidations removing duplicates and redundant grants (**WARNING**: this is experimental)

   @param filter allows you to filter PDs:

     * Use an object eg `{ resource: 'document' }` as the `_.matches` iteratee shorthand.
       If this `_.matches` object is used, the props used for filtering are considered "default" and are omitted from each PD.

     * OR use a function returning boolean for each PD, eg (pd) => pd.resource === 'document'

     See https://lodash.com/docs/4.17.11#filter

   @param consolidateFlag is **experimental**, it tries to consolidate PermissionDefinitions, remove duplicates and merge compatible ones
  */
  public getDefinitions(
    filter?: {
      [key: string]: any;
    },
    consolidateFlag: boolean | 'force' = false
  ): Partial<PermissionDefinitionInternal<Tid, Tid>>[] {
    const filteredPDs = _f.flow(
      _f.filter(filter),
      _f.reject((opd) => _.isEmpty(opd.grant))
    )(this._permissionDefinitionsInternal);

    const resultPDs = consolidateFlag
      ? consolidatePermissionDefinitions(
          filter,
          consolidateFlag
        )(_.cloneDeep(this._permissionDefinitionsInternal))
      : filteredPDs;

    const resultedSaPermissions = new Permissions({
      permissionDefinitions: resultPDs,
      permissionDefinitionDefaults: filter,
    }).build();

    const filteredInstancePermissions = new Permissions({
      permissionDefinitions: filteredPDs as any,
      permissionDefinitionDefaults: filter,
    }).build();

    const difference = this.compare(resultedSaPermissions, filteredInstancePermissions);

    if (difference !== undefined) {
      throw new Error(
        `SA-Permissions: getDefinitions diff:
          ${stringify(difference)}

         Existing grants:
          ${stringify(this.getGrants())}

         Generated grants:
          ${stringify(resultedSaPermissions.getGrants())}
        `
      );
    }

    return resultPDs;
  }

  private ensureHasBuild() {
    if (!this._acre)
      throw new Error(
        `SA-Permissions InvalidInvocation: calling permissions methods before having build()`
      );
  }

  private ensureHasNotBuild() {
    if (this._acre)
      throw new Error(
        `SA-Permissions InvalidInvocation: calling addDefinitions() after having build()`
      );
  }

  /**
   *
   * @param pdi a PermissionDefinitionInternal
   * @param strict true means we dont care if redefining action is _.equal. Duplicating is bad enough!
   */
  private filterPDsWithDuplicateGrantActions = (
    pdi: PermissionDefinitionInternal<Tid, Tid>,
    strict = false
  ) =>
    _.filter(
      this._permissionDefinitionsInternal,
      (originalIpd) =>
        _.isEqual(originalIpd.resource, pdi.resource) &&
        _.some(pdi.roles, (ipdToAddRole) => _.includes(originalIpd.roles, ipdToAddRole)) &&
        _.some(
          pdi.grant,
          (attributes, action) =>
            !!originalIpd.grant[action] &&
            (strict || !_.isEqual(originalIpd.grant[action], pdi.grant[action]))
        )
    );
}
