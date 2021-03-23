import * as _ from 'lodash';
import { AccessControl, IAccessInfo } from 'accesscontrol';
import { AccessControlRe } from 'accesscontrol-re';
import { EPossession, TGrants, Tid } from './types';
import {
  PermissionDefinitionInternal,
  PermissionDefinition,
  PermissionDefinitionDefaults,
} from './PermissionDefinitions';
import { getLogger } from './logger';

export const stringify = (obj) => JSON.stringify(obj, null, 2);

export const hasSomeOwnGrant = (ipd: PermissionDefinitionInternal<Tid, Tid>) =>
  _.some(ipd.grant, (attrs, action): any => _.endsWith(action, `:${EPossession.own}`));

export const projectPDWithDefaultsToInternal = _.curry(
  <TUserId extends Tid, TResourceId extends Tid>(
    defaults: PermissionDefinitionDefaults,
    pd: PermissionDefinition<TUserId, TResourceId>
  ): PermissionDefinitionInternal<TUserId, TResourceId> => {
    const { isOwner, listOwned, limitOwned, descr } = pd;

    const roles = pd.roles || defaults.roles;
    const resource = pd.resource || defaults.resource;

    // prettier-ignore
    if (!roles) throw new Error(`SA-Permissions: InvalidPermissionDefinitionError: missing "roles" in ${stringify(pd)}.`);
    // prettier-ignore
    if (!resource) throw new Error(`SA-Permissions: InvalidPermissionDefinitionError: missing "resource" in ${stringify(pd)}.`);
    // prettier-ignore
    if (_.isEmpty(pd.grant)) throw new Error(`SA-Permissions: InvalidPermissionDefinitionError: missing or empty "grant" in ${stringify(pd)}`);

    // convert ['list', 'ofActions'] to {list: null, ofActions: null}
    const grantTempObj = !_.isArray(pd.grant)
      ? pd.grant
      : _.reduce(
          pd.grant,
          (acc, cur) => {
            acc[cur] = null;
            return acc;
          },
          {}
        );

    // apply defaults
    const grant: TGrants = _.reduce(
      grantTempObj,
      (acc, possibleAttributes, actionPerhapsWithPossession: string) => {
        const [action, possiblePossession] = actionPerhapsWithPossession.split(':');
        const possession: string =
          possiblePossession || pd.possession || defaults.possession || EPossession.any;
        const actionWithPossession = `${action}:${possession}`;
        acc[actionWithPossession] = possibleAttributes ||
          pd.attributes ||
          defaults.attributes || ['*'];

        return acc;
      },
      {}
    );

    const ipd: PermissionDefinitionInternal<TUserId, TResourceId> = {
      roles: _.isArray(roles) ? roles : [roles],
      resource,
      descr, // will be updated below if empty
      isOwner,
      listOwned,
      limitOwned,
      grant,
    };

    return ipd;
  }
);

export const buildAccessControl = (
  permissionDefinitions: PermissionDefinitionInternal<Tid, Tid>[]
): [AccessControl, AccessControlRe] => {
  if (_.isEmpty(permissionDefinitions))
    throw new Error('SA-Permissions: cant build with empty permissionDefinitions!');

  const acre = new AccessControlRe();
  // first pass: execute only the grant's
  // so all roles are defined
  _.each(permissionDefinitions, (
    pd // {grant, resource, roles}
  ) =>
    _.each(pd.grant, (attributes, actionPossession) => {
      const [action, possession] = actionPossession.split(':');
      const accessInfo: IAccessInfo = {
        action,
        possession,
        attributes,
        role: pd.roles,
        resource: pd.resource,
      };

      // @todo: check it's a valid IAccessInfo - use class-validator
      // - has at least one Role, one Resource
      // - has possession, added either as the default or the grant it self
      getLogger().debug(`addAccessInfo(${stringify(accessInfo)})`);
      acre.addAccessInfo(accessInfo);
    })
  );

  // @todo: second pass: extend roles (already defined on 1st pass)
  _.each(permissionDefinitions, (pd: any) => {
    if (pd.extend) {
      throw new Error(
        'extend is not supported yet, and will not until this is fixed https://github.com/onury/accesscontrol/issues/34#issuecomment-466387586 and the whole extend idea redesigned and tested properly.'
      );
      // this._accessControl.grant(pd.role).extend(pd.extend);
    }
  });

  acre.build();
  return [acre.accessControl, acre];
};

export const isArraySetEqual = (
  ar1: any[],
  ar2: any[],
  comparator1?: (a: any, b: any) => boolean,
  comparator2?: (a: any, b: any) => boolean
) => {
  if (!comparator1) comparator1 = (a, b) => a === b;
  if (!comparator2) comparator2 = _.flip(comparator1);

  return (
    _.isArray(ar1) &&
    _.isArray(ar2) &&
    ar1.length === ar2.length &&
    _.isEmpty(_.differenceWith(ar1, ar2, comparator1 as any)) &&
    _.isEmpty(_.differenceWith(ar2, ar1, comparator2 as any))
  );
};

export const isHash = (o: any): o is object =>
  _.isObjectLike(o) && !_.isArray(o) && !_.isFunction(o);

// Returns true if the keys+values of `o1` are all _.isEqual to `o2`'s corresponding ones
export const isLike = (o1: {} = {}, o2: {} = {}) =>
  _.isEqual(o1, o2) ||
  (isHash(o1) && isHash(o2) && _.every(_.keys(o1), (o1Key) => isLike(o1[o1Key], o2[o1Key])));

// Deletes all object keys with a value of `[]` (empty array)
// note: mutates the object
export const deleteEmptyArrayKeys = (o: object) => {
  if (isHash(o)) {
    _.each(o, (val, key) => {
      if (_.isEqual(val, [])) {
        delete o[key];
      } else deleteEmptyArrayKeys(val);
    });
  }

  return o;
};
