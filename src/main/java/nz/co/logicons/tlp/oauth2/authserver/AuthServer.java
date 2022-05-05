package nz.co.logicons.tlp.oauth2.authserver;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ComponentScans;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.security.core.authority.AuthorityUtils;

import com.google.common.collect.Sets;

import nz.co.logicons.tlp.core.enums.ChildSchemaType;
import nz.co.logicons.tlp.core.enums.SearchOperator;
import nz.co.logicons.tlp.core.genericmodels.nodes.DocumentNode;
import nz.co.logicons.tlp.core.genericmodels.operations.ValidateSchemaOperation;
import nz.co.logicons.tlp.core.genericmodels.schemas.DocumentSchema;
import nz.co.logicons.tlp.core.genericmodels.views.SearchParam;
import nz.co.logicons.tlp.core.mongo.MongoDatastore;
import nz.co.logicons.tlp.core.mongo.TransformOperation;
import nz.co.logicons.tlp.oauth2.authserver.library.document.MongoClientDetails;

/**
 * @author Allen
 *
 */
@SpringBootApplication
@ComponentScans({
    @ComponentScan(basePackages = "nz.co.logicons.tlp.oauth2.authserver"),
    @ComponentScan(basePackages = "nz.co.logicons.tlp.core.config"),
    @ComponentScan(basePackages = "nz.co.logicons.tlp.core.mongo"),
    @ComponentScan(basePackages = "nz.co.logicons.tlp.core.rest")
})
public class AuthServer {
  private static final Logger LOGGER = LoggerFactory.getLogger(AuthServer.class);
  public static void main(String[] args)
  {
    final ConfigurableApplicationContext context = SpringApplication.run(AuthServer.class, args);

    // ApplicationContext applicationContext = SpringApplication.run(SweldoBootApp.class, args);
    // LOGGER.info("\n----------------------------ASCII---------------------------");
    // for (String name : context.getBeanDefinitionNames())
    // {
    // LOGGER.info(name);
    // }
    // LOGGER.info("----------------------------ASCII---------------------------");
    // System.out.println(context.getBean("mongoDatastore"));
    localTestOnly(context);

    if (args.length > 0 && "init".equalsIgnoreCase(args[0]))
    {

      MongoTemplate mongoTemplate = (MongoTemplate) context.getBean(MongoTemplate.class);

      // DB db = mongoTemplate.getDb();
      // QueryBuilder queryBuilder = new QueryBuilder();
      // queryBuilder.put("_id");
      // // queryBuilder.is("6126c3934e5ac7c32344e3e3");
      // queryBuilder.is(new ObjectId("6126c3934e5ac7c32344e3e3"));
      // DBObject query = queryBuilder.get();
      // DBCursor dbCursor = db.getCollection("user").find(query);
      // if (dbCursor.hasNext())
      // {
      // System.out.println(dbCursor.next().toString());
      // }
      // mongoTemplate.dropCollection(MongoUser.class);
      // mongoTemplate.dropCollection(MongoClientDetails.class);
      // mongoTemplate.dropCollection(MongoAccessToken.class);
      // mongoTemplate.dropCollection(MongoAuthorizationCode.class);

      // init the users
      // MongoUser mongoUser = new MongoUser();
      // mongoUser.setUsername("user");
      // mongoUser.setPassword("user");
      // mongoUser.setRoles(Sets.newHashSet(("ROLE_USER")));
      // mongoTemplate.save(mongoUser);

      // init the client details
      MongoClientDetails clientDetails = new MongoClientDetails();
      clientDetails.setClientId("web-client");
      clientDetails.setClientSecret("web-client-secret");
      clientDetails.setSecretRequired(true);
      clientDetails.setResourceIds(Sets.newHashSet("api", "edi"));
      clientDetails.setScope(Sets.newHashSet("read"));
      clientDetails.setAuthorizedGrantTypes(Sets.newHashSet("authorization_code", "refresh_token",
          "password", "client_credentials"));
      clientDetails.setAuthorities(AuthorityUtils.createAuthorityList("ROLE_USER"));
      clientDetails.setAccessTokenValiditySeconds(60 * 60 * 12); // 12 hrs
      clientDetails.setRefreshTokenValiditySeconds(60 * 60 * 24 * 7); // 7 days.
      clientDetails.setAutoApprove(false);
      mongoTemplate.save(clientDetails);

    }
  }
  private static void localTestOnly(final ConfigurableApplicationContext context)
  {
    // String json =
    // "{\"_id\":\"(sequence)\",\"systemlocked\":true,\"children\":[{\"_id\":\"_id\",\"systemlocked\":true,\"type\":\"idschema\"},{\"_id\":\"next\",\"systemlocked\":true,\"type\":\"numberschema\"}]}";
    TransformOperation ts = (TransformOperation) context.getBean("transformOperation");
    MongoDatastore datastore = (MongoDatastore) context.getBean("mongoDatastore");

    List<SearchParam> searchParams = new ArrayList<>();
    searchParams.add(new SearchParam("_id", SearchOperator.equals, ChildSchemaType.sequenceidschema,
        ts.createJsonNode(2)));

    String ss = datastore.getDocumentInStr("(user)", "allen", false);
    System.out.println(ss);
    // searchDocumentNode - can't be use finding (schema)
    Collection<DocumentNode> sch = datastore.getDocuments("TN_Job", searchParams, null, 0, 0);

    DocumentSchema fleetDs = ts.createDocumentSchema(ss);
    ValidateSchemaOperation validateSchemaOperation = (ValidateSchemaOperation) context
        .getBean("validateSchemaOperation");
    validateSchemaOperation.validate(fleetDs);

    // System.out.println("fleetDs " + fleetDs);
    DocumentNode dn = datastore.getDocument("TN_Job", "2", false);
    System.out.println("dnnnnnnnnnnnnnnn " + dn);

    // DocumentNode fleetDn = ts.createDocumentNode(ss, fleetDs);
    // System.out.println(fleetDn.prettyPrintDocumentValues());
    // System.out.println("fleet schema " + sch);
    // DocumentSchema fleetDocSchema = ts.createDocumentSchema(sch);
    // System.out.println(fleetDocSchema);
    // System.out.println(ds);
    String t = "{ \"_id\" : \"(user)\" , \"displaytext\" : \"(user)\" , \"inline\" : false , \"systemowned\" : true "
        + ", \"systemlocked\" : false , \"cached\" : false , \"skipvalidation\" : false "
        + ", \"children\" : [ { \"type\" : \"idschema\" , \"validators\" : [ { \"type\" : \"requiredvalidator\" , \"params\" : { }} , { \"type\" : \"idvalidator\" , \"params\" : { }}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true , \"id\" : true} , \"displaytext\" : \"_id\" , \"_id\" : \"_id\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"stringschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"firstname\" , \"_id\" : \"firstname\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"stringschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"lastname\" , \"_id\" : \"lastname\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"stringschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"email\" , \"_id\" : \"email\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"rolesschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true} , \"displaytext\" : \"roles\" , \"_id\" : \"roles\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"boolschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"active\" , \"_id\" : \"active\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"stringschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"passwordhash\" , \"_id\" : \"passwordhash\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"stringschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"passwordsalt\" , \"_id\" : \"passwordsalt\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"stringschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"remembermehash\" , \"_id\" : \"remembermehash\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"datetimeschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"lastlogin\" , \"_id\" : \"lastlogin\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"datetimeschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"lastrememberme\" , \"_id\" : \"lastrememberme\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"numberschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"scale\" : 0 , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"numeric\" : true , \"simple\" : true} , \"displaytext\" : \"cacheid\" , \"_id\" : \"cacheid\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"stringschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"applicationVersion\" , \"_id\" : \"applicationVersion\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"inlineschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"(audit)\" , \"classification\" : { \"nonlist\" : true} , \"displaytext\" : \"audit\" , \"_id\" : \"audit\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"linkedschema\" , \"validators\" : [ { \"type\" : \"linkeddocumentvalidator\" , \"params\" : { \"message\" : \"Invalid\"}}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"AR_Customers\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Customer\" , \"_id\" : \"Customer\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"linkedschema\" , \"validators\" : [ { \"type\" : \"linkeddocumentvalidator\" , \"params\" : { \"message\" : \"Invalid\"}}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"AD_Companies\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Company\" , \"_id\" : \"Company\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"linkedschema\" , \"validators\" : [ { \"type\" : \"linkeddocumentvalidator\" , \"params\" : { \"message\" : \"Invalid\"}}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"RS_Drivers\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Driver\" , \"_id\" : \"Driver\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"linkedschema\" , \"validators\" : [ { \"type\" : \"linkeddocumentvalidator\" , \"params\" : { \"message\" : \"Invalid\"}}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"RS_Depot\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Depot\" , \"_id\" : \"Depot\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"linkedschema\" , \"validators\" : [ { \"type\" : \"linkeddocumentvalidator\" , \"params\" : { \"message\" : \"Invalid\"}}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"SM_Salesperson\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Sales_Person\" , \"_id\" : \"Sales_Person\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"linkedschema\" , \"validators\" : [ { \"type\" : \"linkeddocumentvalidator\" , \"params\" : { \"message\" : \"Invalid\"}}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"WH_Warehouse\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Warehouse\" , \"_id\" : \"Warehouse\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"boolschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Restricted\" , \"_id\" : \"Restricted\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"boolschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"TOBY\" , \"_id\" : \"TOBY\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"inlineschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"AD_Address_Insert\" , \"classification\" : { \"nonlist\" : true} , \"displaytext\" : \"Address\" , \"_id\" : \"Address\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"linkedschema\" , \"validators\" : [ { \"type\" : \"linkeddocumentvalidator\" , \"params\" : { \"message\" : \"Invalid\"}}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"TN_Entity\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Entity\" , \"_id\" : \"Entity\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"moneyschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"scale\" : 2 , \"currency\" : \"NZD\" , \"subtype\" : \"NZD\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"numeric\" : true , \"simple\" : true} , \"displaytext\" : \"PO_Limit\" , \"_id\" : \"PO_Limit\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"linkedschema\" , \"validators\" : [ { \"type\" : \"linkeddocumentvalidator\" , \"params\" : { \"message\" : \"Invalid\"}}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"(user)\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"PO_Supervisor\" , \"_id\" : \"PO_Supervisor\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"linkedschema\" , \"validators\" : [ { \"type\" : \"linkeddocumentvalidator\" , \"params\" : { \"message\" : \"Invalid\"}}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"AD_Contacts\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Contact\" , \"_id\" : \"Contact\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"linkedschema\" , \"validators\" : [ { \"type\" : \"linkeddocumentvalidator\" , \"params\" : { \"message\" : \"Invalid\"}}] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"subtype\" : \"TLP_Menu\" , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Menu\" , \"_id\" : \"Menu\" , \"evaluatedpermissions\" : { }} , { \"type\" : \"stringschema\" , \"validators\" : [ ] , \"systemowned\" : false , \"systemlocked\" : false , \"transientfield\" : false , \"upshiftfield\" : false , \"permissionexclude\" : false , \"classification\" : { \"nonlist\" : true , \"simpleandlistinline\" : true , \"simple\" : true} , \"displaytext\" : \"Menu_Description\" , \"_id\" : \"Menu_Description\" , \"evaluatedpermissions\" : { }}] , \"permissions\" : { \"permissions\" : [ ] , \"permissionprofile\" : \"PROFILE_2\"} , \"evaluatedpermissions\" : { } , \"validators\" : [ ] , \"scripts\" : [ { \"scripttrigger\" : \"OnValidationServer\" , \"scriptlet\" : true , \"scriptletid\" : \"nz.co.spikydev.base.scripting.user.UserRoleValidation\"} , { \"scripttrigger\" : \"OnValidationServer\" , \"scriptlet\" : true , \"scriptletid\" : \"nz.co.spikydev.transport.scripting.user.RestrictedUserRoleValidation\"} , { \"scripttrigger\" : \"AfterSaveServer\" , \"scriptlet\" : true , \"scriptletid\" : \"nz.co.spikydev.transport.scripting.user.UserAfterSavePublishLicenceServer\"} , { \"scripttrigger\" : \"AfterDeleteServer\" , \"scriptlet\" : true , \"scriptletid\" : \"nz.co.spikydev.transport.scripting.user.UserAfterSavePublishLicenceServer\"}] , \"traceable\" : false , \"usage\" : \"[SM_Salesperson, WH_Storeperson, RS_Drivers, FN_Transaction_Header, PO_Order, SM_Issue, (user), AD_Contacts]\"}";
    DocumentSchema fleetDocSchema = ts.createDocumentSchema(t);
    System.out.println("1 " + t);
    System.out.println("2 " + ss);
    System.out.println("3 " + sch);
    System.out.println(StringUtils.equals(t, ss));
    String userSchemaJson = "{\"_id\":\"(user)\",\"children\":[{\"_id\":\"_id\",\"systemlocked\":true,\"type\":\"idschema\""
        + ",\"validators\":[{\"type\":\"regexvalidator\",\"params\":{\"message\":\"Must be lower case or numeric characters\""
        + ",\"regex\":\"[a-z0-9]*\"}}]},{\"_id\":\"firstname\",\"systemlocked\":true,\"type\":\"stringschema\""
        + ",\"validators\":[{\"type\":\"requiredvalidator\"}]},{\"_id\":\"lastname\",\"systemlocked\":true"
        + ",\"type\":\"stringschema\",\"validators\":[{\"type\":\"requiredvalidator\"}]},{\"_id\":\"email\""
        + ",\"systemlocked\":true,\"type\":\"stringschema\",\"validators\":[{\"type\":\"requiredvalidator\"}"
        + ",{\"type\":\"emailvalidator\"}]},{\"_id\":\"roles\",\"systemlocked\":true,\"type\":\"rolesschema\"}"
        + ",{\"_id\":\"active\",\"systemlocked\":true,\"type\":\"boolschema\"},{\"_id\":\"TOBY\""
        + ",\"systemlocked\":true,\"type\":\"boolschema\"},{\"_id\":\"passwordhash\""
        + ",\"systemlocked\":true,\"type\":\"stringschema\"},{\"_id\":\"passwordsalt\""
        + ",\"systemlocked\":true,\"type\":\"stringschema\"},{\"_id\":\"remembermehash\""
        + ",\"systemlocked\":true,\"type\":\"stringschema\"},{\"_id\":\"lastlogin\""
        + ",\"systemlocked\":true,\"type\":\"datetimeschema\"},{\"_id\":\"lastrememberme\""
        + ",\"systemlocked\":true,\"type\":\"datetimeschema\"},{\"_id\":\"cacheid\""
        + ",\"systemlocked\":true,\"type\":\"numberschema\"},{\"_id\":\"applicationVersion\""
        + ",\"systemlocked\":true,\"type\":\"stringschema\"}],\"scripts\":[{\"scripttrigger\":\"OnValidationServer\""
        + ",\"scriptlet\":true,\"scriptletid\":\"nz.co.spikydev.base.scripting.user.UserRoleValidation\"}]}";
    // String user = "{\"_id\": \"allen\", \"roles\": {\"roles\": [\"SYSADMIN\", \"LOOKUP\"]"
    // + ", \"predefined\": true, \"system\": false, \"sysadmin\": true, \"siteadmin\": true}"
    // + ", \"active\": true, \"firstname\": \"Logicons\", \"lastname\": \"Services\""
    // + ", \"email\": \"trevor@logicons.co.nz\", \"audit\": {\"changedby\": \"SYSTEM\""
    // + ", \"changedon\": \"2021-09-01T10:51:46.405\", \"logicaldelete\": false"
    // + ", \"parentid\": \"allen\", \"childid\": \"53a3c944975a7e6ee75b62b1\""
    // + ", \"createdby\": \"admin\", \"createdon\": \"2019-09-23T13:46:20.371\"}"
    // + ", \"Menu\": \"TL0000000000\", \"lastlogin\": \"2021-09-01T10:51:46.393\""
    // + ", \"lastrememberme\": \"2020-05-04T19:26:04.469\", \"Address\": {\"parentid\": \"allen\""
    // + ", \"childid\": \"591e47aa99bcb30f2453eed8\", \"Stocking_Point\": false}, \"Restricted\": false"
    // + ", \"TOBY\": false, \"Sales_Person\": \"Trev the second\", \"PO_Limit\": 10000.0"
    // + ", \"passwordhash\": \"1ac96e803b755fb3c716b0fbc39f4fce71da4085ae7452e8af1e4c4634978094\""
    // + ", \"passwordsalt\":
    // \"Ѕ櫓Ꙇ莍椷ἐ薳曔㛓ऌ\\ue309끦㫠賑嚯쪩낪域䟑蹝\\u0a84ꆀ摩ꨤ뮧䥠푳㶩\\ud8c1\\udc7e똷깣섬籑醸寽팀겢酂穛\\udb3d\\udc74洙\\uf743伏\\u1a5bᡅ\\uf19e倞唹岂\\ue862\\ue307伏덍朖ꁙ㺥쨑闹痷粊㽸돇\",
    // \"remembermehash\": \"e50482dcfbfb9aa5af8b08eac5940dc6bb0fb4815881567a2c8548d9919917a9\"}";
    DocumentSchema ds = ts.createDocumentSchema(userSchemaJson);
    System.out.println(ds);
    // DocumentNode docNode = ts.createDocumentNode(user, ds);
    // System.out.println(docNode.prettyPrintDocumentValues());
    // System.out.println("DONEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE");
    // List<DocumentNode> docNodes = ts.createDocumentNodes("[" + user + "]", ds);
    // System.out.println(docNodes);
    // System.out.println(ts.getJson(docNode));
    //
    // String searchjson =
    // "[{\"fieldid\":\"User\",\"searchoperator\":\"equals\",\"value\":\"allen\",\"childschematype\":\"stringschema\"}]";
    // List<SearchParam> searchParams = ts.createSearchParams(searchjson);
    // System.out.println(searchParams);
    //
    // String jsonnodes = "[{\"_id\": \"Accounts Administration\", \"displaytext\": \"Accounts Administration\",
    // \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Address
    // Administration\", \"displaytext\": \"Address Administration\", \"predefined\": false, \"system\": false,
    // \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Client\", \"displaytext\": \"Client\", \"predefined\":
    // false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Demo\", \"displaytext\":
    // \"Demo\", \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\":
    // \"Depot\", \"displaytext\": \"Depot\", \"predefined\": false, \"system\": false, \"sysadmin\": false,
    // \"siteadmin\": false},{\"_id\": \"Financial Administration\", \"displaytext\": \"Financial Administration\",
    // \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Financials
    // Processing\", \"displaytext\": \"Financials Processing\", \"predefined\": false, \"system\": false,
    // \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Inventory Processing\", \"displaytext\": \"Inventory
    // Processing\", \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\":
    // \"Job Administration\", \"displaytext\": \"Job Administration\", \"predefined\": false, \"system\": false,
    // \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Licence - Calendar\", \"displaytext\": \"Licence -
    // Calendar\", \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\":
    // \"Licence - Container Yard\", \"displaytext\": \"Licence - Container Yard\", \"predefined\": false,
    // \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Licence - Debtors\",
    // \"displaytext\": \"Licence - Debtors\", \"predefined\": false, \"system\": false, \"sysadmin\": false,
    // \"siteadmin\": false},{\"_id\": \"Licence - Financials\", \"displaytext\": \"Licence - Financials\",
    // \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Licence -
    // Fleet\", \"displaytext\": \"Licence - Fleet\", \"predefined\": false, \"system\": false, \"sysadmin\": false,
    // \"siteadmin\": false},{\"_id\": \"Licence - Inventory\", \"displaytext\": \"Licence - Inventory\",
    // \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Licence -
    // Projects\", \"displaytext\": \"Licence - Projects\", \"predefined\": false, \"system\": false, \"sysadmin\":
    // false, \"siteadmin\": false},{\"_id\": \"Licence - Transport\", \"displaytext\": \"Licence - Transport\",
    // \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Licence -
    // Warehouse\", \"displaytext\": \"Licence - Warehouse\", \"predefined\": false, \"system\": false,
    // \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Products Administration\", \"displaytext\": \"Products
    // Administration\", \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\":
    // false},{\"_id\": \"Project Processing\", \"displaytext\": \"Project Processing\", \"predefined\": false,
    // \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Rating Administration\",
    // \"displaytext\": \"Rating Administration\", \"predefined\": false, \"system\": false, \"sysadmin\": false,
    // \"siteadmin\": false},{\"_id\": \"Resources Administration\", \"displaytext\": \"Resources Administration\",
    // \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Sales
    // Management\", \"displaytext\": \"Sales Management\", \"predefined\": false, \"system\": false, \"sysadmin\":
    // false, \"siteadmin\": false},{\"_id\": \"Subby\", \"displaytext\": \"Subby\", \"predefined\": false,
    // \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Support\", \"displaytext\":
    // \"Support\", \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\":
    // \"System Supervisor\", \"displaytext\": \"System Supervisor\", \"predefined\": false, \"system\": false,
    // \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Transport Administration\", \"displaytext\":
    // \"Transport Administration\", \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\":
    // false},{\"_id\": \"WMS Client Inward\", \"displaytext\": \"WMS Client Inward\", \"predefined\": false,
    // \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"WMS Client Outward\",
    // \"displaytext\": \"WMS Client Outward\", \"predefined\": false, \"system\": false, \"sysadmin\": false,
    // \"siteadmin\": false},{\"_id\": \"Warehouse Management\", \"displaytext\": \"Warehouse Management\",
    // \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Workshop
    // Processing\", \"displaytext\": \"Workshop Processing\", \"predefined\": false, \"system\": false,
    // \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Job No Delete\", \"displaytext\": \"Job No Delete\",
    // \"predefined\": false, \"system\": false, \"sysadmin\": false, \"siteadmin\": false},{\"_id\": \"Manifest
    // Person\", \"displaytext\": \"Manifest Person\", \"predefined\": false, \"system\": false, \"sysadmin\":
    // false, \"siteadmin\": false}]";
    // List<JsonNode> jsonNodes = ts.createJsonNodes(jsonnodes);
    // System.out.println(jsonNodes);
  }
}
