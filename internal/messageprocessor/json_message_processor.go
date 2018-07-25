package messageprocessor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/carbonblack/cb-event-forwarder/internal/cbapi"
	"github.com/carbonblack/cb-event-forwarder/internal/deepcopy"
	"github.com/carbonblack/cb-event-forwarder/internal/util"
	log "github.com/sirupsen/logrus"
)

type JSONMessageHandlerFunc func(inmsg map[string]interface{}) ([]map[string]interface{}, error)

type JsonMessageProcessor struct {
	DebugFlag       bool
	DebugStore      string
	CbServerURL     string
	EventMap        map[string]bool
	CbAPI           *cbapi.CbAPIHandler
	messageHandlers map[string]JSONMessageHandlerFunc
}

var feedParserRegex = regexp.MustCompile(`^feed\.(\d+)\.(.*)$`)

func parseQueryString(encodedQuery map[string]string) (queryIndex string, parsedQuery string, err error) {
	err = nil

	queryIndex, ok := encodedQuery["index_type"]
	if !ok {
		err = errors.New("no index_type included in query")
		return
	}

	rawQuery, ok := encodedQuery["search_query"]
	if !ok {
		err = errors.New("no search_query included in query")
		return
	}

	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return
	}

	queryArray, ok := query["q"]
	if !ok {
		err = errors.New("no 'q' query parameter provided")
		return
	}

	parsedQuery = queryArray[0]
	return
}

func handleKeyValues(msg map[string]interface{}) {
	var alliance_data_map = make(map[string]map[string]interface{}, 0)
	for key, value := range msg {
		switch {
		case strings.Contains(key, "alliance_"):
			alliance_data := strings.Split(key, "_")
			alliance_data_source := alliance_data[2]
			alliance_data_key := alliance_data[1]
			alliance_map, alreadyexists := alliance_data_map[alliance_data_source]
			if alreadyexists {
				alliance_map[alliance_data_key] = value
			} else {
				temp := make(map[string]interface{})
				temp[alliance_data_key] = value
				alliance_data_map[alliance_data_source] = temp
			}
			delete(msg, key)
		case key == "endpoint":
			endpointstr := ""
			switch value.(type) {
			case string:
				endpointstr = value.(string)
			case []interface{}:
				endpointstr = value.([]interface{})[0].(string)
			}
			parts := strings.Split(endpointstr, "|")
			hostname := parts[0]
			sensorID := parts[1]
			msg["hostname"] = hostname
			msg["sensor_id"] = sensorID
			delete(msg, "endpoint")
		case key == "highlights_by_doc":
			delete(msg, "highlights_by_doc")
		case key == "highlights":
			delete(msg, "highlights")
		/*case key == "event_timestamp":
		msg["timestamp"] = value
		delete(msg, "event_timestamp")*/
		case key == "timestamp":
			msg["event_timestamp"] = value
			delete(msg, "timestamp")
		case key == "computer_name":
			msg["hostname"] = value
			delete(msg, "computer_name")
		case key == "md5" || key == "parent_md5" || key == "process_md5":
			if md5, ok := value.(string); ok {
				if len(md5) == 32 {
					msg[key] = strings.ToUpper(md5)
				}
			}
		case key == "ioc_type":
			// if the ioc_type is a map and it contains a key of "md5", uppercase it
			v := reflect.ValueOf(value)
			if v.Kind() == reflect.Map && v.Type().Key().Kind() == reflect.String {
				iocType := value.(map[string]interface{})
				if md5value, ok := iocType["md5"]; ok {
					if md5, ok := md5value.(string); ok {
						if len(md5) != 32 && len(md5) != 0 {
							log.WithFields(log.Fields{"MD5 Length": len(md5)}).Warn("MD5 Length was not valid")
						}
						iocType["md5"] = strings.ToUpper(md5)
					}
				}
			} else {
				if iocType, ok := value.(string); ok {
					if iocType == "query" {
						// decode the IOC query
						if rawIocValue, ok := msg["ioc_value"].(string); ok {
							var iocValue map[string]string
							if json.Unmarshal([]byte(rawIocValue), &iocValue) == nil {
								if queryIndex, rawQuery, err := parseQueryString(iocValue); err == nil {
									msg["ioc_query_index"] = queryIndex
									msg["ioc_query_string"] = rawQuery
								}
							}
						}
					}
				}
			}
		case key == "comms_ip" || key == "interface_ip":
			if value, ok := value.(json.Number); ok {
				ipaddr, err := strconv.ParseInt(value.String(), 10, 32)
				if err == nil {
					msg[key] = util.GetIPv4AddressSigned(int32(ipaddr))
				}
			}
		}
	}
	if len(alliance_data_map) > 0 {
		msg["alliance_data"] = alliance_data_map
	}
}

func (jsp *JsonMessageProcessor) addLinksToMessage(msg map[string]interface{}) {
	if jsp.CbServerURL == "" {
		return
	}

	// add sensor links when applicable
	if value, ok := msg["sensor_id"]; ok {
		if value, ok := value.(json.Number); ok {
			hostID, err := strconv.ParseInt(value.String(), 10, 32)
			if err == nil {
				msg["link_sensor"] = fmt.Sprintf("%s#/host/%d", jsp.CbServerURL, hostID)
			}
		}
	}

	// add binary links when applicable
	for _, key := range [...]string{"md5", "parent_md5", "process_md5"} {
		if value, ok := msg[key]; ok {
			if md5, ok := value.(string); ok {
				if len(md5) == 32 {
					keyName := "link_" + key
					msg[keyName] = fmt.Sprintf("%s#/binary/%s", jsp.CbServerURL, msg[key])
				}
			}
		}
	}

	// add process links
	if processGUID, ok := msg["process_guid"]; ok {
		if processID, segmentID, err := util.ParseFullGUID(processGUID.(string)); err == nil {
			msg["link_process"] = fmt.Sprintf("%s#analyze/%v/%v", jsp.CbServerURL, processID, segmentID)
		}
	}

	if parentGUID, ok := msg["parent_guid"]; ok {
		if parentID, segmentID, err := util.ParseFullGUID(parentGUID.(string)); err == nil {
			msg["link_parent"] = fmt.Sprintf("%s#analyze/%v/%v", jsp.CbServerURL, parentID, segmentID)
		}
	}
}

func fixupMessageType(routingKey string) string {
	if feedParserRegex.MatchString(routingKey) {
		return fmt.Sprintf("feed.%s", feedParserRegex.FindStringSubmatch(routingKey)[2])
	}
	return routingKey
}

func (jsp *JsonMessageProcessor) ProcessJSONMessage(msg map[string]interface{}, routingKey string) ([]map[string]interface{}, error) {
	messageType := fixupMessageType(routingKey)

	if processfunc, ok := jsp.messageHandlers[messageType]; ok {
		outmsgs, err := processfunc(msg)

		// add links for each message
		for _, outmsg := range outmsgs {
			jsp.addLinksToMessage(outmsg)
		}
		return outmsgs, err
	}

	return nil, nil
}

/*
 * PostprocessJSONMessage performs postprocessing on feed/watchlist/alert messages.
 * For exmaple, for feed hits we need to grab the report_title.
 * To do this we must query the Cb Response Server's REST API to get the report_title.  NOTE: In order to do this
 * functionality we need the Cb Response Server URL and API Token set within the config.
 */
func (jsp *JsonMessageProcessor) PostprocessJSONMessage(msg map[string]interface{}) map[string]interface{} {

	feedID, feedIDPresent := msg["feed_id"]
	reportID, reportIDPresent := msg["report_id"]

	/*
		:/p			 * First make sure these fields are present
	*/
	if feedIDPresent && reportIDPresent {
		/*
		 * feedID should be of type json.Number which is typed as a string
		 * reportID should be of type string as well
		 */
		if reflect.TypeOf(feedID).Kind() == reflect.String &&
			reflect.TypeOf(reportID).Kind() == reflect.String {
			iFeedID, err := feedID.(json.Number).Int64()
			if err == nil {
				/*
				 * Get the report_title for this feed hit
				 */
				reportTitle, reportScore, reportLink, err := jsp.CbAPI.GetReport(int(iFeedID), reportID.(string))
				log.Debugf("Report title = %s , Score = %d, link = %s", reportTitle, reportScore, reportLink)
				if err == nil {
					/*
					 * Finally save the report_title into this message
					 */
					msg["report_title"] = reportTitle
					msg["report_score"] = reportScore
					msg["report_link"] = reportLink
					/*
						log.Infof("report title for id %s:%s == %s\n",
							feedID.(json.Number).String(),
							reportID.(string),
							reportTitle)
					*/
				}

			} else {
				log.Info("Unable to convert feed_id to int64 from json.Number")
			}

		} else {
			log.Info("Feed Id was an unexpected type")
		}
	}
	return msg
}

func getString(m map[string]interface{}, k string, dv string) string {
	if val, ok := m[k]; ok {
		if strval, ok := val.(string); ok {
			return strval
		}
	}
	return dv
}

func getNumber(m map[string]interface{}, k string, dv json.Number) json.Number {
	if val, ok := m[k]; ok {
		if numval, ok := val.(json.Number); ok {
			return numval
		}
	}
	return dv
}

func getIPAddress(m map[string]interface{}, k string, dv string) string {
	if val, ok := m[k]; ok {
		if numval, ok := val.(json.Number); ok {
			ipaddr, err := strconv.ParseInt(numval.String(), 10, 32)
			if err == nil {
				return util.GetIPv4AddressSigned(int32(ipaddr))
			}
		} else if strval, ok := val.(string); ok {
			return strval
		}
	}
	return dv
}

func copySensorMetadata(subdoc map[string]interface{}, outmsg map[string]interface{}) {
	// sensor metadata
	outmsg["sensor_id"] = getNumber(subdoc, "sensor_id", json.Number("0"))
	outmsg["hostname"] = getString(subdoc, "hostname", "")
	outmsg["group"] = getString(subdoc, "group", "")
	outmsg["comms_ip"] = getIPAddress(subdoc, "comms_ip", "")
	outmsg["interface_ip"] = getIPAddress(subdoc, "interface_ip", "")
	outmsg["host_type"] = getString(subdoc, "host_type", "")
	outmsg["os_type"] = getString(subdoc, "os_type", "")
}

func copyProcessMetadata(subdoc map[string]interface{}, outmsg map[string]interface{}) {
	// process metadata
	outmsg["process_md5"] = strings.ToUpper(getString(subdoc, "process_md5", ""))
	outmsg["process_guid"] = getString(subdoc, "unique_id", "")
	outmsg["process_name"] = getString(subdoc, "process_name", "")
	outmsg["cmdline"] = getString(subdoc, "cmdline", "")
	outmsg["process_pid"] = getNumber(subdoc, "process_pid", json.Number("0"))
	outmsg["username"] = getString(subdoc, "username", "")
	outmsg["path"] = getString(subdoc, "path", "")
	outmsg["last_update"] = getString(subdoc, "last_update", "")
	outmsg["start"] = getString(subdoc, "start", "")
}

func copyParentMetadata(subdoc map[string]interface{}, outmsg map[string]interface{}) {
	// parent process metadata
	outmsg["parent_name"] = getString(subdoc, "parent_name", "")
	outmsg["parent_guid"] = getString(subdoc, "parent_unique_id", "")
	outmsg["parent_pid"] = getNumber(subdoc, "parent_pid", json.Number("0"))
}

func copyEventCounts(subdoc map[string]interface{}, outmsg map[string]interface{}) {
	// process event counts at the time the watchlist/feed/alert hit occurred
	for _, count := range []string{
		"modload_count", "filemod_count", "regmod_count", "emet_count",
		"netconn_count", "crossproc_count", "processblock_count",
		"childproc_count",
	} {
		outmsg[count] = getNumber(subdoc, count, json.Number("0"))
	}
}

func (jsp *JsonMessageProcessor) watchlistHitProcess(inmsg map[string]interface{}) ([]map[string]interface{}, error) {
	// collect fields that are used across all the docs
	watchlistName := getString(inmsg, "watchlist_name", "")
	watchlistID := getNumber(inmsg, "watchlist_id", json.Number("0"))
	cbVersion := getString(inmsg, "cb_version", "")
	eventTimestamp := getNumber(inmsg, "event_timestamp", json.Number("0"))

	outmsgs := make([]map[string]interface{}, 0, 1)

	// explode watchlist/feed hit messages that include a "docs" array
	if val, ok := inmsg["docs"]; ok {
		if subdocs, ok := val.([]interface{}); ok {
			for _, submsg := range subdocs {
				if subdoc, ok := submsg.(map[string]interface{}); ok {
					outmsg := make(map[string]interface{})

					// message metadata
					outmsg["type"] = "watchlist.hit.process"
					outmsg["schema_version"] = 2

					// watchlist metadata
					outmsg["watchlist_name"] = watchlistName
					outmsg["watchlist_id"] = watchlistID

					// event metadata
					outmsg["cb_version"] = cbVersion
					outmsg["event_timestamp"] = eventTimestamp

					copySensorMetadata(subdoc, outmsg)
					copyProcessMetadata(subdoc, outmsg)
					copyParentMetadata(subdoc, outmsg)
					copyEventCounts(subdoc, outmsg)

					// append the message to our output
					outmsgs = append(outmsgs, outmsg)
				}
			}
		}
	}

	return outmsgs, nil
}

func (jsp *JsonMessageProcessor) watchlistStorageHitProcess(inmsg map[string]interface{}) ([]map[string]interface{}, error) {
	// collect fields that are used across all the docs
	watchlistName := getString(inmsg, "watchlist_name", "")
	watchlistID := getNumber(inmsg, "watchlist_id", json.Number("0"))
	cbVersion := getString(inmsg, "cb_version", "")
	eventTimestamp := getNumber(inmsg, "event_timestamp", json.Number("0"))

	outmsgs := make([]map[string]interface{}, 0, 1)

	// explode watchlist/feed hit messages that include a "docs" array
	if val, ok := inmsg["docs"]; ok {
		if subdocs, ok := val.([]interface{}); ok {
			for _, submsg := range subdocs {
				if subdoc, ok := submsg.(map[string]interface{}); ok {
					outmsg := make(map[string]interface{})

					// message metadata
					outmsg["type"] = "watchlist.storage.hit.process"
					outmsg["schema_version"] = 2

					// watchlist metadata
					outmsg["watchlist_name"] = watchlistName
					outmsg["watchlist_id"] = watchlistID

					// event metadata
					outmsg["cb_version"] = cbVersion
					outmsg["event_timestamp"] = eventTimestamp

					// sensor metadata not available in .storage.hit events

					copyProcessMetadata(subdoc, outmsg)
					copyParentMetadata(subdoc, outmsg)
					copyEventCounts(subdoc, outmsg)

					// append the message to our output
					outmsgs = append(outmsgs, outmsg)
				}
			}
		}
	}

	return outmsgs, nil
}

// ProcessJSON will take an incoming message and create a set of outgoing key/value
// pairs ready for the appropriate output function
func (jsp *JsonMessageProcessor) ProcessJSON(routingKey string, indata []byte) ([]map[string]interface{}, error) {
	var msg map[string]interface{}

	decoder := json.NewDecoder(bytes.NewReader(indata))

	// Ensure that we decode numbers in the JSON as integers and *not* float64s
	decoder.UseNumber()

	if err := decoder.Decode(&msg); err != nil {
		return nil, err
	}

	return jsp.ProcessJSONMessage(msg, routingKey)
}

func NewJSONProcessor(newConfig Config) *JsonMessageProcessor {
	jmp := new(JsonMessageProcessor)
	jmp.DebugFlag = newConfig.DebugFlag
	jmp.DebugStore = newConfig.DebugStore
	jmp.EventMap = deepcopy.Iface(newConfig.EventMap).(map[string]bool)
	jmp.CbServerURL = newConfig.CbServerURL
	jmp.CbAPI = newConfig.CbAPI

	// create message handlers
	jmp.messageHandlers = make(map[string]JSONMessageHandlerFunc)
	jmp.messageHandlers["watchlist.hit.process"] = jmp.watchlistHitProcess
	jmp.messageHandlers["watchlist.storage.hit.process"] = jmp.watchlistStorageHitProcess

	return jmp
}
