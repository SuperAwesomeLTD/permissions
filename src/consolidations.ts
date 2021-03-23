// 3rd
import * as _ from 'lodash';
import * as _f from 'lodash/fp';
import { AccessControl } from 'accesscontrol';

// own
import { buildAccessControl, hasSomeOwnGrant, isArraySetEqual, isLike } from './utils';
import { PermissionDefinitionInternal } from './PermissionDefinitions';
import { getLogger } from './logger';
import { Tid } from './types';

export const mergeTwoPermissions = (
  receivingPD: PermissionDefinitionInternal<Tid, Tid>,
  pd: PermissionDefinitionInternal<Tid, Tid>
): PermissionDefinitionInternal<Tid, Tid> => {
  // @todo: throw if !canPermissionsBeMerged
  const result = {
    ...receivingPD,
    ...pd,
    grant: {
      ...receivingPD.grant,
      ...pd.grant,
    },
  };

  return result;
};

export const areCompatibleOwnHooks = (
  pd1: PermissionDefinitionInternal<Tid, Tid>,
  pd2: PermissionDefinitionInternal<Tid, Tid>
) =>
  (pd1.isOwner === pd2.isOwner || !pd1.isOwner || !pd2.isOwner) &&
  (pd1.listOwned === pd2.listOwned || !pd1.listOwned || !pd2.listOwned);

export const consolidatePermissions = _f.reduce(
  (consolidatedCPDs: PermissionDefinitionInternal<Tid, Tid>[], cpd: PermissionDefinitionInternal<Tid, Tid>) => {
    const matchingPds = _.filter(
      consolidatedCPDs,
      (consolidatedCpd: PermissionDefinitionInternal<Tid, Tid>) =>
        isArraySetEqual(consolidatedCpd.roles, cpd.roles, _.isEqual) &&
        consolidatedCpd.resource === cpd.resource &&
        areCompatibleOwnHooks(consolidatedCpd, cpd)
    );

    if (_.isEmpty(matchingPds)) {
      consolidatedCPDs.push(cpd);
    } else if (matchingPds.length === 1) {
      // consolidate the two
      const idx = _.indexOf(consolidatedCPDs, matchingPds[0]);
      consolidatedCPDs[idx] = mergeTwoPermissions(consolidatedCPDs[idx] as any, cpd as any);
    } else
      throw new Error(
        'Something is wrong with _internalPermissionDefinitions - we have duplicated consolidated PDs'
      );

    return consolidatedCPDs;
  }
);

export const deleteDefinedGrants = _f.reduce(
  // refactor, not needs to be reducer, just a visitor to delete grant  props
  (consolidatedCPDs: PermissionDefinitionInternal<Tid, Tid>[], cpd: PermissionDefinitionInternal<Tid, Tid>) => {
    const [accessControl] = _.isEmpty(consolidatedCPDs)
      ? [new AccessControl()] // dummy
      : buildAccessControl(consolidatedCPDs);

    // check if grant for all roles is already defined and delete it!
    _.each(cpd.grant, (attributes, action) => {
      const grantExists = _.every(cpd.roles, (role) => {
        try {
          const perm = accessControl.permission({
            action,
            resource: cpd.resource,
            role,
          });

          return perm.granted && _.isEqual(perm.attributes, attributes);
        } catch (error) {
          return false; // ignore errors of roles missing etc, simply means its not defined
        }
      });

      if (grantExists) delete cpd.grant[action];
    });

    // add anyway, it will be eliminated if it ends up empty
    consolidatedCPDs.push(cpd);

    return consolidatedCPDs;
  }
);

export const mergeCompatibleGrants = (pds: PermissionDefinitionInternal<Tid, Tid>[]) => {
  // for every parent PD, find ones below it that have the a super set with the same exact grants
  for (let parentIdx = 0; parentIdx < pds.length; parentIdx++) {
    const parentPd = pds[parentIdx];
    for (let childIdx = parentIdx + 1; childIdx < pds.length; childIdx++) {
      const childPd = pds[childIdx];
      if (parentPd.resource === childPd.resource && isLike(parentPd.grant, childPd.grant)) {
        // delete ALL child grants that exist in parent (and are seen as moved there)
        // add all roles of child to parent
        parentPd.roles = _.uniq([...parentPd.roles, ...childPd.roles]);
        _.each(_.keys(parentPd.grant), (actionKey) => delete childPd.grant[actionKey]);
      }
    }
  }

  return pds;
};

export const consolidatePermissionDefinitions = (filter, consolidateFlag: boolean | 'force') =>
  _f.flow(
    _f.filter(filter),
    _f.tap((ipds: PermissionDefinitionInternal<Tid, Tid>[]) => {
      if (_.some(ipds, hasSomeOwnGrant)) {
        const msg = `getDefinitions() with consolidate = true PermissionDefinitions is **experimental** and NOT compatible when Possession.own is used ('force' is needed)!
        Use "getDefinitions()" with consolidate = false to avoid consolidations.`;
        if (consolidateFlag === true)
          throw new Error(
            `SA-Permissions: ${msg} Use "getDefinitions()" with consolidate = 'force' to proceed with consolidations of own, at your own risk.`
          );
        if (consolidateFlag === 'force') getLogger().warn(msg);
      }
    }),
    consolidatePermissions([]) as any,
    deleteDefinedGrants([]) as any,
    mergeCompatibleGrants,
    _f.map(
      _f.omitBy(
        // omit keys of filter & empty ones
        (val: any, key) =>
          (_.isEmpty(val) && !_.isFunction(val)) ||
          (_.isObjectLike(filter) &&
            (_.isEqual(filter[key], val) || isArraySetEqual(filter[key], val)))
      )
    ),
    // eliminate PDs with empty grants
    _f.reject((pd: PermissionDefinitionInternal<Tid, Tid>) => _.isEmpty(pd.grant))
  );
